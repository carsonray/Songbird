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
    : self(this), name(std::move(name)), processMode(mode), nextSeqNum(0), missingPacketTimeoutMs(100)
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

void SongbirdCore::setAllowOutofOrder(bool allow) {
    if (allowOutofOrder == allow) return;
    allowOutofOrder = allow;
    if (allow) {
        // Clears remote ordering map
        remoteOrders.clear();
    }
}

void SongbirdCore::holdPacket(const Packet& packet) {
    std::vector<uint8_t> bytes = packet.toBytes(processMode);
    appendToWriteBuffer(bytes.data(), bytes.size());
}

void SongbirdCore::sendPacket(Packet& packet) {
    sendPacket(packet, nextSeqNum.fetch_add(1));
}
void SongbirdCore::sendPacket(Packet& packet, uint8_t sequenceNum) {
    // Attaches sequence number if in packet mode
    if (processMode == PACKET) {
        packet.setSequenceNum(sequenceNum);
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
    parseData(data, length, IPAddress(), 0);
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length, IPAddress remoteIP, uint16_t remotePort) {
    if (processMode == PACKET) {
        // Parses full packet
        auto pkt = packetFromData(data, length);
        if (!pkt) return;
        pkt->setRemote(remoteIP, remotePort);

        std::vector<std::shared_ptr<Packet>> dispatch;
        if (allowOutofOrder) {
            dispatch.push_back(pkt);
            SpinLockGuard guard(dataSpinlock);
            // If any remaining packets in incoming packets add to dispatch
            for (const auto &p: incomingPackets) {
                dispatch.push_back(p.second);
            }
        } else {
            SpinLockGuard guard(dataSpinlock);
            const Remote remote = pkt->getRemote();
            // If it is a new remote and ordering mode is on, add to remote order map
            auto it = remoteOrders.find(remote);
            if (it == remoteOrders.end()) {
                TimeoutID id{this, remote};
                RemoteOrder order {pkt->getSequenceNum(), id};
                remoteOrders[remote] = order;
            }
            const RemoteExpected expected{pkt->getRemote(), pkt->getSequenceNum()};
            incomingPackets[expected] = pkt;

            dispatch = reorderPackets();
        }

        // Call handlers on dispatched packets
        for (auto& p : dispatch) {
            callHandlers(p);
        }
    } else if (processMode == STREAM) {
        // Adds data to readBuffer
        appendToReadBuffer(data, length);
        // Process complete or incomplete packets in readBuffer
        while (true) {
            std::shared_ptr<Packet> pkt = packetFromStream();
            if (!pkt) {
                if (millis() - lastDataTimeMs > missingPacketTimeoutMs) {
                    // Timeout: clear read buffer to avoid stale data
                    flush();
                }
                break;
            }
            lastDataTimeMs = millis();
            pkt->setRemote(remoteIP, remotePort);
            callHandlers(pkt);
        }
    }
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::packetFromData(const uint8_t* data, std::size_t length) {
    std::shared_ptr<SongbirdCore::Packet> pkt;
    if (length < 2) return pkt;
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

std::vector<std::shared_ptr<SongbirdCore::Packet>> SongbirdCore::reorderPackets()
{
    SpinLockGuard guard(dataSpinlock);
    std::vector<std::shared_ptr<Packet>> dispatch;

    // Iterating through remotes
    for (auto itOrder = remoteOrders.begin(); itOrder != remoteOrders.end(); ++itOrder)
    {
        Remote r = itOrder->first;
        RemoteOrder& order = itOrder->second;   // ← REFERENCE, not copy

        auto remotePackets = reorderRemote(r, order);
        dispatch.insert(dispatch.end(), remotePackets.begin(), remotePackets.end());
    }

    return dispatch;
}

std::vector<std::shared_ptr<SongbirdCore::Packet>> SongbirdCore::reorderRemote(const SongbirdCore::Remote r, SongbirdCore::RemoteOrder& order) {
    std::vector<std::shared_ptr<SongbirdCore::Packet>> dispatch;
    while (true)
    {
        const RemoteExpected key{ r, order.expectedSeqNum };
        auto itPkt = incomingPackets.find(key);

        // Checks for packet with correct sequence number
        if (itPkt != incomingPackets.end())
        {
            dispatch.push_back(itPkt->second);
            incomingPackets.erase(itPkt);
            order.expectedSeqNum++;
            if (order.missingTimerActive) {
                xTimerStop(order.missingTimer, 0);
                order.missingTimerActive = false;
            }
            continue;
        }

        unsigned long nowMs = millis();

        // No packets with correct sequence, starting timeout
        if (!order.missingTimerActive)
        {
            order.missingTimerActive = true;
            order.missingTimer = startMissingTimer(order);
            break;
        }

        break;
    }
    return dispatch;
}

TimerHandle_t SongbirdCore::startMissingTimer(RemoteOrder& order)
{
    TimerHandle_t handle = xTimerCreate(
        "missingTimer",
        pdMS_TO_TICKS(missingPacketTimeoutMs),
        pdFALSE, // one-shot
        (void *) &order.timeoutID,
        missingTimerCallback
    );

    // (re)start
    xTimerStop(handle, 0);
    xTimerChangePeriod(handle, pdMS_TO_TICKS(missingPacketTimeoutMs), 0);
    xTimerStart(handle, 0);
    return handle;
}

void SongbirdCore::onMissingTimeout(const Remote remote) {
    std::vector<std::shared_ptr<Packet>> dispatch;
    {
        SpinLockGuard guard(dataSpinlock);
        // Timeout: find nearest forward seqNum for this remote
        bool found = false;
        uint8_t bestDist = 0xFF;
        uint8_t bestSeq = 0;

        // Finds remote order from map
        auto it = remoteOrders.find(remote);
        if (it == remoteOrders.end()) return;
        RemoteOrder& order = it->second;

        for (auto &p : incomingPackets)
        {
            if (p.first.remote != remote) continue;

            uint8_t seq = p.first.seqNum;
            uint8_t dist = uint8_t(seq - order.expectedSeqNum);

            if (!found || dist < bestDist)
            {
                found = true;
                bestDist = dist;
                bestSeq = seq;
            }
        }

        if (found)
        {
            order.expectedSeqNum = bestSeq;
            order.missingTimerActive = false;
            dispatch = reorderRemote(remote, order);
        } else {
            // No packets for this remote — delete it safely
            remoteOrders.erase(it);
            remoteMap.erase(remote);
        }
    }

    // Call handlers on dispatched packets
    for (auto& p : dispatch) {
        callHandlers(p);
    }
}

void missingTimerCallback (TimerHandle_t xTimer) {
    // Retrieve the SongbirdCore + Remote key
    auto *ctx = static_cast<SongbirdCore::TimeoutID*>(pvTimerGetTimerID(xTimer));

    // Mark that this remote timed out
    ctx->owner->onMissingTimeout(ctx->remote);
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
    uint8_t currPayloadLen = readBuffer[1];
    if (readBuffer.size() < 2 + static_cast<std::size_t>(readBuffer[1])) return pkt;
    newPacket = true;
    // we have a full packet in readBuffer; construct it
    uint8_t currHeader = readBuffer[0];

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
    if (remoteHandler) remoteHandler(pkt);
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

std::size_t SongbirdCore::getNumIncomingPackets() {
    SpinLockGuard guard(dataSpinlock);
    return incomingPackets.size();
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