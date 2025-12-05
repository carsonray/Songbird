#include <Arduino.h>
#include "SongbirdCore.h"

#include <algorithm>
#include <cassert>

/// Packet implementation
SongbirdCore::Packet::Packet(uint8_t header)
    : header(header), sequenceNum(0), payloadLength(0), payload(), readPos(0) {}

SongbirdCore::Packet::Packet(uint8_t header, const std::vector<uint8_t>& payload)
    : header(header), sequenceNum(0), payloadLength(payload.size()), payload(payload), readPos(0) {}

std::vector<uint8_t> SongbirdCore::Packet::toBytes(SongbirdCore::ProcessMode mode) const {
    std::vector<uint8_t> out;
    out.reserve(2 + payloadLength);
    out.push_back(header);
    if (mode == SongbirdCore::STREAM) {
        // Length is needed for stream framing
        out.push_back(static_cast<uint8_t>(payloadLength));
    } else if (mode == SongbirdCore::PACKET) {
        // In packet mode, length is implicit but sequence number is needed to preserve ordering
        out.push_back(sequenceNum);
    }
    
    if (!payload.empty()) {
        out.insert(out.end(), payload.begin(), payload.end());
    }
    return out;
}

void SongbirdCore::Packet::setSequenceNum(uint8_t seqNum) {
    sequenceNum = seqNum;
}

uint8_t SongbirdCore::Packet::getHeader() const {
    return header;
}

uint8_t SongbirdCore::Packet::getSequenceNum() const {
    return static_cast<int64_t>(sequenceNum);
}

std::vector<uint8_t> SongbirdCore::Packet::getPayload() const {
    return payload;
}

std::size_t SongbirdCore::Packet::getPayloadLength() const {
    return payloadLength;
}

std::size_t SongbirdCore::Packet::getRemainingBytes() const {
    return payload.size() - readPos;
}

void SongbirdCore::Packet::setRemote(const IPAddress& ip, uint16_t port) {
    remoteIP = ip;
    remotePort = port;
}

SongbirdCore::Remote SongbirdCore::Packet::getRemote() const {
    Remote remote {remoteIP, remotePort};
    return remote;
}

IPAddress SongbirdCore::Packet::getRemoteIP() const {
    return remoteIP;
}

uint16_t SongbirdCore::Packet::getRemotePort() const {
    return remotePort;
}

void SongbirdCore::Packet::writeBytes(const uint8_t* buffer, std::size_t length) {
    if (length == 0) return;
    payload.insert(payload.end(), buffer, buffer + length);
    payloadLength = payload.size();
}

void SongbirdCore::Packet::writeByte(uint8_t value) {
    payload.push_back(value);
    payloadLength = payload.size();
}

void SongbirdCore::Packet::writeInt16(int16_t data) {
    uint8_t buf[2];
    buf[0] = static_cast<uint8_t>((data >> 8) & 0xFF);
    buf[1] = static_cast<uint8_t>(data & 0xFF);
    writeBytes(buf, 2);
}

void SongbirdCore::Packet::writeFloat(float value) {
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

uint8_t SongbirdCore::Packet::readByte() {
    if (readPos >= payload.size()) return 0;
    return payload[readPos++];
}

uint8_t SongbirdCore::Packet::peekByte() const {
    if (readPos >= payload.size()) return 0;
    return payload[readPos];
}

void SongbirdCore::Packet::readBytes(uint8_t* buffer, std::size_t len) {
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

float SongbirdCore::Packet::readFloat() {
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

int16_t SongbirdCore::Packet::readInt16() {
    uint8_t buf[2] = {0,0};
    readBytes(buf, 2);
    int16_t val = static_cast<int16_t>(static_cast<uint16_t>(buf[1]) | (static_cast<uint16_t>(buf[0]) << 8));
    return val;
}

// SongbirdCore implementation

SongbirdCore::SongbirdCore(std::string name, SongbirdCore::ProcessMode mode)
    : name(std::move(name)), processMode(mode), nextSeqNum(0), missingPacketTimeoutMs(100)
{
    // initialize spinlocks
    dataSpinlock = portMUX_INITIALIZER_UNLOCKED;
}

SongbirdCore::~SongbirdCore() {
    flush();
}

void SongbirdCore::attachStream(IStream* stream) {
    this->stream = stream;
}

void SongbirdCore::setReadHandler(ReadHandler handler) {
    SpinLockGuard guard(dataSpinlock);
    readHandler = std::move(handler);
}

void SongbirdCore::setHeaderHandler(uint8_t header, ReadHandler handler) {
    SpinLockGuard guard(dataSpinlock);
    headerHandlers[header] = std::move(handler);
}

void SongbirdCore::clearHeaderHandler(uint8_t header) {
    SpinLockGuard guard(dataSpinlock);
    headerHandlers.erase(header);
    headerMap.erase(header);
}

void SongbirdCore::setRemoteHandler(IPAddress remoteIP, uint16_t remotePort, ReadHandler handler) {
    SpinLockGuard guard(dataSpinlock);
    Remote remote{remoteIP, remotePort};
    remoteHandlers[remote] = std::move(handler);
}

void SongbirdCore::clearRemoteHandler(IPAddress remoteIP, uint16_t remotePort) {
    SpinLockGuard guard(dataSpinlock);
    Remote remote{remoteIP, remotePort};
    remoteHandlers.erase(remote);
    remoteMap.erase(remote);
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::waitForHeader(uint8_t header, uint32_t timeoutMs) {
    // First check if a header is already available
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = headerMap.find(header);
        if (it != headerMap.end()) {
            auto pkt = it->second;
            headerMap.erase(it);
            return pkt;
        }
    }

    unsigned long start = millis();
    while ((millis() - start) < timeoutMs) {
        {
            SpinLockGuard guard(dataSpinlock);
            auto it = headerMap.find(header);
            if (it != headerMap.end()) {
                auto pkt = it->second;
                headerMap.erase(it);
                return pkt;
            }
        }
        vTaskDelay(1);
    }
    return nullptr;
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::waitForRemote(IPAddress remoteIP, uint16_t remotePort, uint32_t timeoutMs) {
    Remote remote {remoteIP, remotePort};
    // First check if a packet is already available
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = remoteMap.find(remote);
        if (it != remoteMap.end()) {
            auto pkt = it->second;
            remoteMap.erase(it);
            return pkt;
        }
    }

    unsigned long start = millis();
    while ((millis() - start) < timeoutMs) {
        {
            SpinLockGuard guard(dataSpinlock);
            auto it = remoteMap.find(remote);
            if (it != remoteMap.end()) {
                auto pkt = it->second;
                remoteMap.erase(it);
                return pkt;
            }
        }
        vTaskDelay(1);
    }
    return nullptr;
}

SongbirdCore::Packet SongbirdCore::createPacket(uint8_t header) {
    return Packet(header);
}

void SongbirdCore::setMissingPacketTimeout(uint32_t ms) {
    SpinLockGuard guard(dataSpinlock);
    missingPacketTimeoutMs = ms;
}

void SongbirdCore::holdPacket(const Packet& packet) {
    if (processMode == STREAM) {
        std::vector<uint8_t> bytes = packet.toBytes(processMode);
        appendToWriteBuffer(bytes.data(), bytes.size());
    }
}

void SongbirdCore::sendPacket(Packet& packet) {
    // Attaches sequence number if in packet mode
    if (processMode == PACKET) {
        packet.setSequenceNum(nextSeqNum.fetch_add(1));
    }
    holdPacket(packet);
    sendAll();
}

void SongbirdCore::sendAll() {
    // attempt immediate send if stream available
    if (stream && stream->isOpen()) {
        std::vector<uint8_t> localBuf;
        {
            SpinLockGuard guard(dataSpinlock);
            if (!writeBuffer.empty()) {
                localBuf = writeBuffer;
                writeBuffer.clear();
            }
        }

        if (!localBuf.empty()) {
            stream->write(localBuf.data(), localBuf.size());
        }
    }
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length) {
    parseData(data, length, "", 0);
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length, IPAddress remoteIP, uint16_t remotePort) {
    if (processMode == PACKET) {
        // Parses full packet
        auto pkt = packetFromData(data, length);
        if (!pkt) return;
        if (remoteIP != IPAddress()) {
            pkt->setRemote(remoteIP, remotePort);
        }
        {
            SpinLockGuard guard(dataSpinlock);
            Remote remote = pkt->getRemote();
            // If it is a new remote, add to remote order map
            auto it = remoteOrders.find(remote);
            if (it == remoteOrders.end()) {
                RemoteOrder order {pkt->getSequenceNum(), false, 0};
                remoteOrders[remote] = order;
            }

            RemoteExpected expected{pkt->getRemote(), pkt->getSequenceNum()};
            incomingPackets[expected] = pkt;
        }

        auto dispatch = dispatchPackets();
        
        // Call handlers on dispatched packets
        for (auto& p : dispatch) {
            callHandlers(p);
        }
    } else if (processMode == STREAM) {
        // Process complete or incomplete packets in readBuffer
        while (true) {
            std::shared_ptr<Packet> pkt = packetFromStream();
            if (!pkt) break;
            if (remoteIP != IPAddress()) {
                pkt->setRemote(remoteIP, remotePort);
            }
            callHandlers(pkt);
        }
    }
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::packetFromData(const uint8_t* data, std::size_t length) {
    std::shared_ptr<SongbirdCore::Packet> pkt;
    if (length <= 2) {
        return pkt;
    }
    // Parses packet
    uint8_t currHeader = data[0];
    uint8_t currSeqNum = data[1];
    // For packet mode, payload length is implicit: consume all remaining data
    std::vector<uint8_t> payload;
    if (length > 2) {
        payload.insert(payload.end(), data + 2, data + length);
    }
    pkt = std::make_shared<Packet>(currHeader, payload);
    pkt->setSequenceNum(currSeqNum);
    return pkt;
}

std::vector<std::shared_ptr<SongbirdCore::Packet>> SongbirdCore::dispatchPackets() {
    SpinLockGuard guard(dataSpinlock);
    std::vector<std::shared_ptr<Packet>> dispatch;
    // Process ordered packets from incomingPackets. If the expected packet
    // doesn't arrive within the configured timeout, advance to the next
    // available sequence to avoid blocking forever.
    
    // Keep processing while there's a packet matching expectedSeqNum.
    for (const auto &p : remoteOrders) {
        const Remote r = p.first;
        RemoteOrder o = p.second;
        while (true) {
            RemoteExpected expected{r, o.expectedSeqNum};
            auto it = incomingPackets.find(expected);
            if (it != incomingPackets.end()) {
                // move packet to dispatch list and remove from buffer
                dispatch.push_back(it->second);
                incomingPackets.erase(it);
                o.expectedSeqNum++;
                o.missingTimerActive = false;
                continue;
            }

            // There are unexpected packets or no packets buffered. Start timer if not started
            unsigned long nowMs = millis();
            if (!o.missingTimerActive) {
                o.missingSinceMs = nowMs;
                o.missingTimerActive = true;
                break; // give more time for missing packet to arrive
            }

            auto elapsed = static_cast<int64_t>(nowMs - o.missingSinceMs);
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
                // If packet does not have the same remote ignore it
                if (r != p.first.remote) continue;
                uint8_t key = p.first.expectedSeqNum;
                // distance forward from expectedSeqNum (0 means equal)
                uint8_t dist = static_cast<uint8_t>(key - o.expectedSeqNum);
                if (dist == 0) continue; // would have matched earlier
                if (!found || dist < bestDist) {
                    bestDist = dist;
                    bestKey = key;
                    found = true;
                }
            }
            if (found) {
                // advance expectedSeqNum to the closest available sequence
                o.expectedSeqNum = bestKey;
                o.missingTimerActive = false;
                continue;
            } else {
                // no packets have been sent from the remote in a while
                // so remove it to save memory
                remoteOrders.erase(r);
                remoteMap.erase(r);
                break;
            }
        }
    }
    return dispatch;
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::packetFromStream() {
    SpinLockGuard guard(dataSpinlock);
    std::shared_ptr<SongbirdCore::Packet> pkt;
    if (newPacket) {
        // Must be called with dataMutex locked if used internally; it's safe to call without external lock
        if (readBuffer.size() < 2) return pkt; // need at least header, len

        newPacket = false;
    }
    // Do we have the full payload?
    if (readBuffer.size() < 2 + static_cast<std::size_t>(readBuffer[1])) return pkt;
    newPacket = true;
    // we have a full packet in readBuffer; construct it
    uint8_t currHeader = readBuffer[0];
    uint8_t currPayloadLen = readBuffer[1];

    std::vector<uint8_t> payload;
    payload.insert(payload.end(), readBuffer.begin() + 2, readBuffer.begin() + 2 + currPayloadLen);
    pkt = std::make_shared<Packet>(currHeader, payload);

    // erase consumed bytes
    readBuffer.erase(readBuffer.begin(), readBuffer.begin() + 2 + currPayloadLen);
    return pkt;
}

void SongbirdCore::callHandlers(std::shared_ptr<Packet> pkt) {
    uint8_t header = pkt->getHeader();
    Remote remote = pkt->getRemote();
    // Lookup and store handlers under locks, but invoke them outside locks
    ReadHandler headerHandler = nullptr;
    ReadHandler remoteHandler = nullptr;
    ReadHandler globalHandler = nullptr;
    {
        SpinLockGuard guard(dataSpinlock);

        auto it = headerHandlers.find(header);
        if (it != headerHandlers.end()) headerHandler = it->second;
        // update header map
        headerMap[header] = pkt;

        auto it2 = remoteHandlers.find(remote);
        if (it2 != remoteHandlers.end()) remoteHandler = it2->second;
        // update last remote map
        remoteMap[remote] = pkt;
        
        globalHandler = readHandler;
    }

    if (headerHandler) headerHandler(pkt);
    if (globalHandler) globalHandler(pkt);
}

void SongbirdCore::flush() {
    {
        SpinLockGuard guard(dataSpinlock);
        readBuffer.clear();
        writeBuffer.clear();
        incomingPackets.clear();
        headerMap.clear();
        newPacket = true;
    }
}

std::size_t SongbirdCore::getReadBufferSize() {
    SpinLockGuard guard(dataSpinlock);
    return readBuffer.size();
}

std::size_t SongbirdCore::getWriteBufferSize() {
    SpinLockGuard guard(dataSpinlock);
    return writeBuffer.size();
}

void SongbirdCore::appendToReadBuffer(const uint8_t* data, std::size_t length) {
    SpinLockGuard guard(dataSpinlock);
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}

void SongbirdCore::appendToWriteBuffer(const uint8_t* data, std::size_t length) {
    SpinLockGuard guard(dataSpinlock);
    if (length == 0) return;
    writeBuffer.insert(writeBuffer.end(), data, data + length);
}