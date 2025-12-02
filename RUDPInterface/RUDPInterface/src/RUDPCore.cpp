#include "RUDPCore.h"

#include <algorithm>
#include <cassert>
#include <cstdint>

using namespace std::chrono_literals;

/// Packet implementation
RUDPCore::Packet::Packet() : sequenceNum(0), header(0), payloadLength(0), payload(), readPos(0) {}
RUDPCore::Packet::Packet(uint8_t sequenceNum, uint8_t header)
    : sequenceNum(sequenceNum), header(header), payloadLength(0), payload(), readPos(0) {}

RUDPCore::Packet::Packet(uint8_t sequenceNum, uint8_t header, const std::vector<uint8_t>& payload)
    : sequenceNum(sequenceNum), header(header), payloadLength(payload.size()), payload(payload), readPos(0) {}

std::vector<uint8_t> RUDPCore::Packet::toBytes() const {
    std::vector<uint8_t> out;
    out.reserve(3 + payloadLength);
    out.push_back(static_cast<uint8_t>(sequenceNum));
    out.push_back(header);
    out.push_back(static_cast<uint8_t>(payloadLength));
    if (!payload.empty()) {
        out.insert(out.end(), payload.begin(), payload.end());
    }
    return out;
}

int64_t RUDPCore::Packet::getSequenceNum() const {
    return static_cast<int64_t>(sequenceNum);
}

uint8_t RUDPCore::Packet::getHeader() const {
    return header;
}

std::size_t RUDPCore::Packet::getPayloadLength() const {
    return payloadLength;
}

void RUDPCore::Packet::writeBytes(const uint8_t* buffer, std::size_t length) {
    if (length == 0) return;
    payload.insert(payload.end(), buffer, buffer + length);
    payloadLength = payload.size();
}
void RUDPCore::Packet::writeByte(uint8_t value) {
    payload.push_back(value);
    payloadLength = payload.size();
}

void RUDPCore::Packet::writeFloat(float value) {
    // Serialize float as IEEE-754 32-bit big-endian
    static_assert(sizeof(float) == 4, "Unexpected float size");
    uint32_t iv = 0;
    std::memcpy(&iv, &value, sizeof(iv));
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>((iv >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((iv >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((iv >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(iv & 0xFF);
    writeBytes(buf, sizeof(buf));
}

void RUDPCore::Packet::writeInt16(int16_t data) {
    // Serialize 16-bit integer in big-endian (network) byte order
    uint16_t ud = static_cast<uint16_t>(data);
    uint8_t buf[2];
    buf[0] = static_cast<uint8_t>((ud >> 8) & 0xFF); // high byte first
    buf[1] = static_cast<uint8_t>(ud & 0xFF);        // low byte
    writeBytes(buf, 2);
}

uint8_t RUDPCore::Packet::readByte() {
    if (readPos >= payload.size()) return 0;
    return payload[readPos++];
}

uint8_t RUDPCore::Packet::peekByte() const {
    if (readPos >= payload.size()) return 0;
    return payload[readPos];
}

void RUDPCore::Packet::readBytes(uint8_t* buffer, std::size_t len) {
    if (len == 0) return;
    std::size_t avail = payload.size() - readPos;
    std::size_t toRead = std::min(len, avail);
    if (toRead) {
        std::memcpy(buffer, payload.data() + readPos, toRead);
        readPos += toRead;
    }
    // if requested more than available, zero the rest
    if (toRead < len) {
        std::memset(buffer + toRead, 0, len - toRead);
    }
}

float RUDPCore::Packet::readFloat() {
    // Deserialize 32-bit IEEE-754 float from big-endian byte order
    static_assert(sizeof(float) == 4, "Unexpected float size");
    uint8_t buf[4];
    readBytes(buf, sizeof(buf));
    uint32_t iv = (static_cast<uint32_t>(buf[0]) << 24) |
                  (static_cast<uint32_t>(buf[1]) << 16) |
                  (static_cast<uint32_t>(buf[2]) << 8) |
                  (static_cast<uint32_t>(buf[3]));
    float v = 0.0f;
    std::memcpy(&v, &iv, sizeof(v));
    return v;
}

int16_t RUDPCore::Packet::readInt16() {
    // Deserialize 16-bit integer from big-endian byte order
    uint8_t buf[2] = {0,0};
    readBytes(buf, 2);
    uint16_t uv = (static_cast<uint16_t>(buf[0]) << 8) | static_cast<uint16_t>(buf[1]);
    return static_cast<int16_t>(uv);
}

/// RUDPCore implementation

RUDPCore::RUDPCore(std::string name)
        : name(std::move(name)), stream(nullptr), nextSeqNum(0), expectedSeqNum(0),
            missingPacketTimeoutMs(100), missingSince(), missingTimerActive(false)
{
        // reliability enabled by default
        std::lock_guard<std::mutex> lock(dataMutex);
        reliabilityEnabled = true;
}

RUDPCore::~RUDPCore() {
    flush();
}

void RUDPCore::attachStream(std::shared_ptr<IStream> stream) {
    std::lock_guard<std::mutex> lock(dataMutex);
    this->stream = stream;
}

void RUDPCore::setReadHandler(ReadHandler handler) {
    std::lock_guard<std::mutex> lock(dataMutex);
    readHandler = std::move(handler);
}

void RUDPCore::setResponseHandler(uint8_t header, ReadHandler handler) {
    std::lock_guard<std::mutex> lock(dataMutex);
    responseHandlers[header] = std::move(handler);
}

void RUDPCore::clearResponseHandler(uint8_t header) {
    std::lock_guard<std::mutex> lock(dataMutex);
    responseHandlers.erase(header);
	lastResponseMap.erase(header);
}

std::shared_ptr<RUDPCore::Packet> RUDPCore::waitForHeader(uint8_t header, uint32_t timeoutMs) {
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        // check if we already have a response
        auto it = lastResponseMap.find(header);
        if (it != lastResponseMap.end()) {
            auto pkt = it->second;
            lastResponseMap.erase(it);
            return pkt;
        }
    }
    // wait for condition variable to be signalled with that header
    {
        std::unique_lock<std::mutex> lock2(waitMutex);
        bool got = responseCv.wait_for(lock2, std::chrono::milliseconds(timeoutMs), [&]() {
			std::lock_guard<std::mutex> lock(dataMutex);
            return lastResponseMap.find(header) != lastResponseMap.end();
        });
        if (!got) return nullptr;
    }
	std::lock_guard<std::mutex> lock3(dataMutex);
    auto pkt = lastResponseMap[header];
    lastResponseMap.erase(header);
    return pkt;
}

std::shared_ptr<IStream> RUDPCore::getStream() {
    std::lock_guard<std::mutex> lock(dataMutex);
    return stream;
}

RUDPCore::Packet RUDPCore::createPacket(uint8_t header) {
    uint8_t seq = nextSeqNum.fetch_add(1);
    return Packet(seq, header);
}

void RUDPCore::setMissingPacketTimeout(uint32_t ms) {
    std::lock_guard<std::mutex> lock(dataMutex);
    missingPacketTimeoutMs = ms;
}

void RUDPCore::setReliabilityEnabled(bool enabled) {
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        reliabilityEnabled = enabled;
        // when turning off reliability, reset missing tracker so parser doesn't
        // immediately advance sequences based on old state
        if (!enabled) {
            missingTimerActive = false;
        }
    }
}

bool RUDPCore::isReliabilityEnabled() const {
    std::lock_guard<std::mutex> lock(dataMutex);
    return reliabilityEnabled;
}

void RUDPCore::holdPacket(const Packet& packet) {
    std::vector<uint8_t> bytes = packet.toBytes();
    appendToWriteBuffer(bytes.data(), bytes.size());
}

void RUDPCore::sendPacket(const Packet& packet) {
    std::cout << "(" + name + ") Sending packet: Seq=" << static_cast<int>(packet.getSequenceNum())
              << " Header=0x" << std::hex << static_cast<int>(packet.getHeader())
		<< " Len=" << std::dec << static_cast<int>(packet.getPayloadLength()) << "\n";
    holdPacket(packet);
    sendAll();
}

void RUDPCore::sendAll() {
    auto s = getStream();
    if (!s) return;

    // Move current writeBuffer into a heap-allocated vector so its storage
    // remains valid until the async completion handler runs.
    std::shared_ptr<std::vector<uint8_t>> outBuf;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        if (writeBuffer.empty()) return;
        outBuf = std::make_shared<std::vector<uint8_t>>(std::move(writeBuffer));
        // writeBuffer is now in a valid but unspecified (empty) state; we
        // leave it ready for new data.
        writeBuffer.clear();
    }

    size_t trueBufferSize = outBuf->size();
    s->asyncWrite(outBuf->data(), outBuf->size(),
        [this, outBuf, trueBufferSize](const boost::system::error_code& error, std::size_t bytesTransferred) {
            (void)outBuf; // keep ownership until handler executes
            if (error) {
                std::cerr << "(" + name + ") Error writing bytes: " << error.message() << std::endl;
            }
            else if (bytesTransferred < trueBufferSize) {
                std::cerr << "(" + name + ") Partial write detected. Ensure all bytes are written." << std::endl;
            }
        });
}

void RUDPCore::updateData() {
    // Process complete packets in readBuffer. Depending on reliabilityEnabled
    // we either buffer by sequence (reliable) or dispatch immediately
    std::vector<std::shared_ptr<Packet>> dispatch;
    while (true) {
        std::shared_ptr<Packet> pkt;
        {
            std::lock_guard<std::mutex> lock(dataMutex);
            if (!characterizePacket()) break;
            // we have a full packet in readBuffer; construct it
            std::cout << "(" + name + ") Received packet: Seq=" << static_cast<int>(currSeqNum)
                      << " Header=0x" << std::hex << static_cast<int>(currHeader)
				<< " Len=" << std::dec << static_cast<int>(currPayloadLen) << "\n";

            std::vector<uint8_t> payload;
            if (currPayloadLen)
                payload.insert(payload.end(), readBuffer.begin() + 3, readBuffer.begin() + 3 + currPayloadLen);
            pkt = std::make_shared<Packet>(currSeqNum, currHeader, payload);

            // erase consumed bytes
            readBuffer.erase(readBuffer.begin(), readBuffer.begin() + 3 + currPayloadLen);

            // If reliability disabled, collect for immediate dispatch; otherwise buffer
            if (!reliabilityEnabled) {
                dispatch.push_back(pkt);
            } else {
                incomingPackets[currSeqNum] = pkt;
            }
        }
    }

    // Process ordered packets from incomingPackets. If the expected packet
    // doesn't arrive within the configured timeout, advance to the next
    // available sequence to avoid blocking forever.
    if (reliabilityEnabled) {
        std::lock_guard<std::mutex> lock(dataMutex);
        // Keep processing while there's a packet matching expectedSeqNum.
        while (true) {
            auto it = incomingPackets.find(expectedSeqNum);
            if (it != incomingPackets.end()) {
                // move packet to dispatch list and remove from buffer
                dispatch.push_back(it->second);
                incomingPackets.erase(it);
                expectedSeqNum++;
                missingTimerActive = false;
                continue;
            }

            // No packet with expectedSeqNum currently available
            if (incomingPackets.empty()) {
                // nothing to do, reset timer
                missingTimerActive = false;
                break;
            }

            // There are packets buffered but not the one we expect. Start timer if not started
            auto now = std::chrono::steady_clock::now();
            if (!missingTimerActive) {
                missingSince = now;
                missingTimerActive = true;
                break; // give more time for missing packet to arrive
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - missingSince).count();
            if (elapsed < static_cast<int64_t>(missingPacketTimeoutMs)) {
                // not timed out yet
                break;
            }

            // timed out waiting for expectedSeqNum. Advance to the buffered
            // sequence that is closest forward from expectedSeqNum (wraparound
            // safe). Compute distance as unsigned subtraction so wraparound is
            // handled correctly: dist = (uint8_t)(key - expectedSeqNum).
            uint8_t bestKey = 0;
            uint8_t bestDist = 0;
            bool found = false;
            for (const auto &p : incomingPackets) {
                uint8_t key = p.first;
                // distance forward from expectedSeqNum (0 means equal)
                uint8_t dist = static_cast<uint8_t>(key - expectedSeqNum);
                if (dist == 0) continue; // would have matched earlier
                if (!found || dist < bestDist) {
                    bestDist = dist;
                    bestKey = key;
                    found = true;
                }
            }
            if (found) {
                // advance expectedSeqNum to the closest available sequence
                expectedSeqNum = bestKey;
                missingTimerActive = false;
                continue;
            } else {
                // no suitable packet to advance to
                break;
            }
        }
    } else {
        // If any incoming packets are buffered move to dispatch vector
        std::lock_guard<std::mutex> lock(dataMutex);
        for (auto &p : incomingPackets) {
            dispatch.push_back(p.second);
            incomingPackets.erase(p.first);
        }
    }

    // Dispatch collected in-order packets or immediate packets
    for (auto &p : dispatch) {
        callHandlers(p);
    }

    // Sends any data in write buffer if stream available
    sendAll();
}

void RUDPCore::callHandlers(std::shared_ptr<Packet> pkt) {
    uint8_t header = pkt->getHeader();

    // Copy response handler and update lastResponseMap under responseMutex
    ReadHandler responseHandlerCopy;
    {
        std::lock_guard<std::mutex> rlock(dataMutex);
        auto it = responseHandlers.find(header);
        if (it != responseHandlers.end()) {
            responseHandlerCopy = it->second;
        }
        // update lastResponseMap while holding the same mutex used by waitForResponse
        lastResponseMap[header] = pkt;
    }

    // Call response handler outside of the responseMutex to avoid deadlocks
    if (responseHandlerCopy) {
        try {
            responseHandlerCopy(pkt);
        }
        catch (...) {
            // Swallow exceptions from handlers to avoid terminating the protocol; log if desired.
        }
    }

    // Copy general readHandler under dataMutex, then call it outside the lock
    ReadHandler generalHandlerCopy;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        generalHandlerCopy = readHandler;
    }
    if (generalHandlerCopy) {
        try {
            generalHandlerCopy(pkt);
        }
        catch (...) {
            // Swallow exceptions from handlers to avoid terminating the protocol; log if desired.
        }
    }
}

void RUDPCore::flush() {
    std::lock_guard<std::mutex> lock(dataMutex);
    readBuffer.clear();
    writeBuffer.clear();
    incomingPackets.clear();
    lastResponseMap.clear();
    newPacket = true;
}

std::size_t RUDPCore::getReadBufferSize() {
    std::lock_guard<std::mutex> lock(dataMutex);
    return readBuffer.size();
}

std::size_t RUDPCore::getWriteBufferSize() {
    std::lock_guard<std::mutex> lock(dataMutex);
    return writeBuffer.size();
}

bool RUDPCore::characterizePacket() {
    if (newPacket) {
        // Must be called with dataMutex locked if used internally; it's safe to call without external lock
        if (readBuffer.size() < 3) return false; // need at least seq, header, len
        // Peek bytes
        currSeqNum = readBuffer[0];
        currHeader = readBuffer[1];
        currPayloadLen = readBuffer[2];

        newPacket = false;
    }
    // Do we have the full payload?
    if (readBuffer.size() < 3 + static_cast<std::size_t>(currPayloadLen)) return false;
    newPacket = true;
    return true;
}

void RUDPCore::appendToReadBuffer(const uint8_t* data, std::size_t length) {
	std::lock_guard<std::mutex> lock(dataMutex);
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}

void RUDPCore::appendToWriteBuffer(const uint8_t* data, std::size_t length) {
	std::lock_guard<std::mutex> lock(dataMutex);
    if (length == 0) return;
    writeBuffer.insert(writeBuffer.end(), data, data + length);
}