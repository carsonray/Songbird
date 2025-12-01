// ...existing code...
#include <Arduino.h>
#include "RUDPCore.h"

#include <algorithm>
#include <cassert>

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
    // Store float in IEEE-754 big-endian byte order
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(float));
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>((bits >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((bits >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((bits >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>(bits & 0xFF);
    writeBytes(buf, 4);
}

void RUDPCore::Packet::writeInt16(int16_t data) {
    uint8_t buf[2];
    buf[0] = static_cast<uint8_t>(data & 0xFF);
    buf[1] = static_cast<uint8_t>((data >> 8) & 0xFF);
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
    uint8_t buf[4];
    readBytes(buf, 4);
    uint32_t bits = (static_cast<uint32_t>(buf[0]) << 24) |
                    (static_cast<uint32_t>(buf[1]) << 16) |
                    (static_cast<uint32_t>(buf[2]) << 8)  |
                    (static_cast<uint32_t>(buf[3]));
    float v;
    std::memcpy(&v, &bits, sizeof(float));
    return v;
}

int16_t RUDPCore::Packet::readInt16() {
    uint8_t buf[2] = {0,0};
    readBytes(buf, 2);
    int16_t val = static_cast<int16_t>(static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8));
    return val;
}

/// RUDPCore implementation

RUDPCore::RUDPCore(std::string name)
    : name(std::move(name)), stream(nullptr), nextSeqNum(0), expectedSeqNum(0),
        missingPacketTimeoutMs(100), missingSinceMs(0), missingTimerActive(false)
{
    // initialize spinlocks
    dataSpinlock = portMUX_INITIALIZER_UNLOCKED;
    responseSpinlock = portMUX_INITIALIZER_UNLOCKED;

    // reliability enabled by default
    {
        SpinLockGuard guard(dataSpinlock);
        reliabilityEnabled = true;
    }
}

RUDPCore::~RUDPCore() {
    flush();
}

void RUDPCore::attachStream(std::shared_ptr<IStream> stream) {
    SpinLockGuard guard(dataSpinlock);
    this->stream = stream;
}

void RUDPCore::setReadHandler(ReadHandler handler) {
    SpinLockGuard guard(dataSpinlock);
    readHandler = std::move(handler);
}

void RUDPCore::setResponseHandler(uint8_t header, ReadHandler handler) {
    SpinLockGuard guard(responseSpinlock);
    responseHandlers[header] = std::move(handler);
}

void RUDPCore::clearResponseHandler(uint8_t header) {
    SpinLockGuard guard(responseSpinlock);
    responseHandlers.erase(header);
}

std::shared_ptr<RUDPCore::Packet> RUDPCore::waitForResponse(uint8_t header, uint32_t timeoutMs) {
    // First check if a response is already available
    {
        SpinLockGuard guard(responseSpinlock);
        auto it = lastResponseMap.find(header);
        if (it != lastResponseMap.end()) {
            auto pkt = it->second;
            lastResponseMap.erase(it);
            return pkt;
        }
    }

    unsigned long start = millis();
    while ((millis() - start) < timeoutMs) {
        {
            SpinLockGuard guard(responseSpinlock);
            auto it = lastResponseMap.find(header);
            if (it != lastResponseMap.end()) {
                auto pkt = it->second;
                lastResponseMap.erase(it);
                return pkt;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    return nullptr;
}

std::shared_ptr<IStream> RUDPCore::getStream() {
    SpinLockGuard guard(dataSpinlock);
    return stream;
}

RUDPCore::Packet RUDPCore::createPacket(uint8_t header) {
    uint8_t seq = nextSeqNum.fetch_add(1);
    return Packet(seq, header);
}

void RUDPCore::setMissingPacketTimeout(uint32_t ms) {
    SpinLockGuard guard(dataSpinlock);
    missingPacketTimeoutMs = ms;
}

void RUDPCore::setReliabilityEnabled(bool enabled) {
    {
        SpinLockGuard guard(dataSpinlock);
        reliabilityEnabled = enabled;
        // when turning off reliability, reset missing tracker so parser doesn't
        // immediately advance sequences based on old state
        if (!enabled) {
            missingTimerActive = false;
        }
    }
}

bool RUDPCore::isReliabilityEnabled() const {
    SpinLockGuard guard(dataSpinlock);
    return reliabilityEnabled;
}

void RUDPCore::holdPacket(const Packet& packet) {
    std::vector<uint8_t> bytes = packet.toBytes();
    {
        SpinLockGuard guard(dataSpinlock);
        appendToWriteBuffer(bytes.data(), bytes.size());
    }
    // Clears last response with same header
    {
        SpinLockGuard rguard(responseSpinlock);
        lastResponseMap.erase(packet.getHeader());
    }
}

void RUDPCore::sendPacket(const Packet& packet) {
    holdPacket(packet);
    sendAll();
}

void RUDPCore::sendAll() {
    // attempt immediate send if stream available
    std::shared_ptr<IStream> s = getStream();
    if (s) {
        std::vector<uint8_t> localBuf;
        {
            SpinLockGuard guard(dataSpinlock);
            if (!writeBuffer.empty()) {
                localBuf = writeBuffer;
                writeBuffer.clear();
            }
        }
        if (!localBuf.empty()) {
            s->write(localBuf.data(), localBuf.size());
        }
    }
}

void RUDPCore::updateData() {
    // Pull bytes from stream into readBuffer. Don't hold spinlock while
    // performing I/O on the stream; copy bytes into readBuffer under lock.
    std::shared_ptr<IStream> s = getStream();
    if (s) {
        std::size_t avail = s->available();
        if (avail > 0) {
            std::vector<uint8_t> tmp(avail);
            std::size_t got = s->read(tmp.data(), avail);
            if (got > 0) {
                SpinLockGuard guard(dataSpinlock);
                appendToReadBuffer(tmp.data(), got);
            }
        }
    }

    // Process complete packets in readBuffer. Depending on reliabilityEnabled
    // we either buffer by sequence (reliable) or dispatch immediately
    std::vector<std::shared_ptr<Packet>> dispatch;
    while (true) {
        std::shared_ptr<Packet> pkt;
        {
            SpinLockGuard guard(dataSpinlock);
            if (!characterizePacket()) break;
            // we have a full packet in readBuffer; construct it

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
        SpinLockGuard guard(dataSpinlock);
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
            unsigned long nowMs = millis();
            if (!missingTimerActive) {
                missingSinceMs = nowMs;
                missingTimerActive = true;
                break; // give more time for missing packet to arrive
            }

            auto elapsed = static_cast<int64_t>(nowMs - missingSinceMs);
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
        SpinLockGuard guard(dataSpinlock);
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
    // Lookup and store handlers under locks, but invoke them outside locks
    ReadHandler respHandler = nullptr;
    {
        SpinLockGuard guard(responseSpinlock);
        auto it = responseHandlers.find(header);
        if (it != responseHandlers.end()) respHandler = it->second;
        // update last response map
        lastResponseMap[header] = pkt;
    }

    ReadHandler globalHandler = nullptr;
    {
        SpinLockGuard guard(dataSpinlock);
        globalHandler = readHandler;
    }

    if (respHandler) respHandler(pkt);
    if (globalHandler) globalHandler(pkt);
}

void RUDPCore::flush() {
    {
        SpinLockGuard guard(dataSpinlock);
        readBuffer.clear();
        writeBuffer.clear();
        incomingPackets.clear();
    }
    {
        SpinLockGuard rguard(responseSpinlock);
        lastResponseMap.clear();
    }
}

std::size_t RUDPCore::getReadBufferSize() {
    SpinLockGuard guard(dataSpinlock);
    return readBuffer.size();
}

std::size_t RUDPCore::getWriteBufferSize() {
    SpinLockGuard guard(dataSpinlock);
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
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}

void RUDPCore::appendToWriteBuffer(const uint8_t* data, std::size_t length) {
    if (length == 0) return;
    writeBuffer.insert(writeBuffer.end(), data, data + length);
}