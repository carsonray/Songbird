#include <Arduino.h>
#include "SongbirdCore.h"

#include <algorithm>
#include <cassert>

/// Packet implementation
SongbirdCore::Packet::Packet(uint8_t header)
    : header(header), sequenceNum(0), payloadLength(0), payload(), readPos(0), guaranteedFlag(false) {}

SongbirdCore::Packet::Packet(uint8_t header, const std::vector<uint8_t>& payload)
    : header(header), sequenceNum(0), payloadLength(payload.size()), payload(payload), readPos(0), guaranteedFlag(false) {}

std::vector<uint8_t> SongbirdCore::Packet::toBytes(SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode) const {
    std::vector<uint8_t> out;
    
    if (reliableMode == SongbirdCore::RELIABLE) {
        // RELIABLE mode: no seq/guaranteed bytes
        // STREAM: [header][length][payload]
        // PACKET: [header][payload]
        size_t headerSize = (mode == SongbirdCore::STREAM) ? 2 : 1;
        out.reserve(headerSize + payloadLength);
        out.push_back(header);
        if (mode == SongbirdCore::STREAM) {
            // Length is needed for stream framing
            out.push_back(static_cast<uint8_t>(payloadLength));
        }
    } else {
        // UNRELIABLE mode: includes seq/guaranteed bytes
        // STREAM: [header][length][seq][guaranteed][payload] = 4 + payload
        // PACKET: [header][seq][guaranteed][payload] = 3 + payload
        size_t headerSize = (mode == SongbirdCore::STREAM) ? 4 : 3;
        out.reserve(headerSize + payloadLength);
        out.push_back(header);
        if (mode == SongbirdCore::STREAM) {
            // Length is needed for stream framing
            out.push_back(static_cast<uint8_t>(payloadLength));
            // Add sequence number for guaranteed delivery
            out.push_back(sequenceNum);
        } else if (mode == SongbirdCore::PACKET) {
            // In packet mode, length is implicit but sequence number is needed to preserve ordering
            out.push_back(sequenceNum);
        }

        // Add guaranteed flag byte (0 or 1)
        out.push_back(guaranteedFlag ? 1 : 0);
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

void SongbirdCore::Packet::setRemote(const Remote& remote) {
    remoteIP = remote.ip;
    remotePort = remote.port;
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

SongbirdCore::SongbirdCore(std::string name, SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode)
    : self(this), name(std::move(name)), processMode(mode), reliableMode(reliableMode), nextSeqNum(0), missingPacketTimeoutMs(50), retransmitTimeoutMs(50), maxRetransmitAttempts(5)
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
    // Reserved ACK header enforcement
    if (header == 0x00) {
        Serial.println("Error: Header 0x00 is reserved for ACK and cannot have a handler.");
        return;
    }
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
    // Reserved ACK header enforcement
    if (header == 0x00) {
        Serial.println("Error: Header 0x00 is reserved for ACK and cannot be created manually.");
        // Fallback: create a non-reserved packet to avoid crashing, but warn.
        return Packet(0xFF);
    }
    return Packet(header);
}

void SongbirdCore::setMissingPacketTimeout(uint32_t ms) {
    SpinLockGuard guard(dataSpinlock);
    missingPacketTimeoutMs = ms;
}

void SongbirdCore::setRetransmitTimeout(uint32_t ms) {
    SpinLockGuard guard(dataSpinlock);
    retransmitTimeoutMs = ms;
}

void SongbirdCore::setMaxRetransmitAttempts(uint8_t attempts) {
    SpinLockGuard guard(dataSpinlock);
    maxRetransmitAttempts = attempts;
}

void SongbirdCore::setAllowOutofOrder(bool allow) {
    if (allowOutofOrder == allow) return;
    allowOutofOrder = allow;
}

void SongbirdCore::sendPacket(Packet& packet, bool guaranteeDelivery) {
    sendPacket(packet, nextSeqNum.fetch_add(1), guaranteeDelivery);
}
void SongbirdCore::sendPacket(Packet& packet, uint8_t sequenceNum, bool guaranteeDelivery) {
    if (!stream || !stream->isOpen()) {
        Serial.println("Error: No stream attached or stream is not open. Cannot send packet.");
        return;
    }
    
    // Attach sequence number in both modes
    packet.setSequenceNum(sequenceNum);

    // Set guaranteed flag if needed
    if (guaranteeDelivery) {
        packet.setGuaranteed(true);
    }
    
    // Write directly to stream in both modes
    std::vector<uint8_t> bytes = packet.toBytes(processMode, reliableMode);
    Remote remote = packet.getRemote();
    bool supportsRemote = stream->supportsRemoteWrite();
    if (supportsRemote && remote.port != 0) {
        stream->writeToRemote(bytes.data(), bytes.size(), remote.ip, remote.port);
    } else {
        stream->write(bytes.data(), bytes.size());
    }

    // Track guaranteed packets and start retransmit timer (UNRELIABLE mode only)
    if (guaranteeDelivery && reliableMode == UNRELIABLE) {
        Remote remote = packet.getRemote();
        // If packet doesn't have a valid remote, use the stream's default remote
        if (supportsRemote && remote.port == 0) {
            IPAddress defaultIP;
            uint16_t defaultPort;
            if (stream->getDefaultRemote(defaultIP, defaultPort)) {
                remote.ip = defaultIP;
                remote.port = defaultPort;
                packet.setRemote(remote);
            }
        }
        RemoteExpected remoteExpected{remote, sequenceNum};
        OutgoingInfo info{std::make_shared<Packet>(packet), remote, nullptr, 0};
        {
            SpinLockGuard guard(dataSpinlock);
            outgoingGuaranteed[sequenceNum] = info;
        }
        startRetransmitTimer(sequenceNum);
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

        // Check for ACK and handle guaranteed delivery before buffering/dispatching
        // This ensures ACKs are sent immediately even if packet gets buffered as out-of-order
        if (checkForAck(pkt)) {
            return; // Was an ACK packet, already handled
        }

        std::vector<std::shared_ptr<Packet>> dispatch;
        if (allowOutofOrder || reliableMode == RELIABLE) {
            dispatch.push_back(pkt);
            if (reliableMode == UNRELIABLE) {
                // Update remoteOrders only for guaranteed packets (for repeat detection)
                if (pkt->isGuaranteed()) {
                    updateRemoteOrder(pkt);
                }
                SpinLockGuard guard(dataSpinlock);
                // If any remaining packets in incoming packets add to dispatch
                for (const auto &p: incomingPackets) {
                    dispatch.push_back(p.second);
                }
                // Clear incomingPackets after dispatching them
                incomingPackets.clear();
            }
        } else if (reliableMode == UNRELIABLE) {
            // If it is a new remote and ordering mode is on, add to remote order map
            // Track sequence numbers for ALL packets in ordering mode
            updateRemoteOrder(pkt);

            {
                SpinLockGuard guard(dataSpinlock);

                const RemoteExpected expected{pkt->getRemote(), pkt->getSequenceNum()};
                incomingPackets[expected] = pkt;
            }

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

            // Check for ACK and handle guaranteed delivery
            if (checkForAck(pkt)) {
                continue; // Was an ACK packet, skip to next packet
            }

            // Updates remote order for UNRELIABLE mode (for all packets for sequencing)
            if (reliableMode == UNRELIABLE) {
                updateRemoteOrder(pkt);
            }
            
            callHandlers(pkt);
        }
    }
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::packetFromData(const uint8_t* data, std::size_t length) {
    std::shared_ptr<SongbirdCore::Packet> pkt;
    
    if (reliableMode == RELIABLE) {
        // RELIABLE mode: [header][payload]
        if (length < 1) return pkt;
        uint8_t currHeader = data[0];
        std::vector<uint8_t> payload;
        if (length > 1) {
            payload.insert(payload.end(), data + 1, data + length);
        }
        pkt = std::make_shared<Packet>(currHeader, payload);
    } else {
        // UNRELIABLE mode: [header][seq][guaranteed][payload]
        if (length < 3) return pkt;  // Need at least header, seq, and guaranteed flag
        uint8_t currHeader = data[0];
        uint8_t currSeqNum = data[1];
        // For packet mode, third byte may be guaranteed flag
        size_t payloadOffset = 3;
        uint8_t guaranteed = data[2];
        // payload length is implicit: consume all remaining data
        std::vector<uint8_t> payload;
        if (length > payloadOffset) {
            payload.insert(payload.end(), data + payloadOffset, data + length);
        }
        pkt = std::make_shared<Packet>(currHeader, payload);
        pkt->setSequenceNum(currSeqNum);
        if (guaranteed) pkt->setGuaranteed();
    }
    return pkt;
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::packetFromStream() {
    SpinLockGuard guard(dataSpinlock);
    std::shared_ptr<SongbirdCore::Packet> pkt;
    
    if (reliableMode == RELIABLE) {
        // RELIABLE mode: [header][length][payload]
        if (newPacket) {
            if (readBuffer.size() < 2) return pkt; // need at least header and length
            newPacket = false;
        }
        // Do we have the full payload?
        uint8_t currPayloadLen = readBuffer[1];
        if (readBuffer.size() < 2 + static_cast<std::size_t>(currPayloadLen)) return pkt;
        newPacket = true;
        // we have a full packet in readBuffer; construct it
        uint8_t currHeader = readBuffer[0];
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), readBuffer.begin() + 2, readBuffer.begin() + 2 + currPayloadLen);
        pkt = std::make_shared<Packet>(currHeader, payload);
        // erase consumed bytes
        readBuffer.erase(readBuffer.begin(), readBuffer.begin() + 2 + currPayloadLen);
    } else {
        // UNRELIABLE mode: [header][length][seq][guaranteed][payload]
        if (newPacket) {
            if (readBuffer.size() < 4) return pkt; // need at least header, len, seq, guaranteed flag
            newPacket = false;
        }
        // Do we have the full payload?
        uint8_t currPayloadLen = readBuffer[1];
        if (readBuffer.size() < 4 + static_cast<std::size_t>(currPayloadLen)) return pkt;
        newPacket = true;
        // we have a full packet in readBuffer; construct it
        uint8_t currHeader = readBuffer[0];
        uint8_t currSeqNum = readBuffer[2];
        uint8_t guaranteed = readBuffer[3];

        std::vector<uint8_t> payload;
        payload.insert(payload.end(), readBuffer.begin() + 4, readBuffer.begin() + 4 + currPayloadLen);
        pkt = std::make_shared<Packet>(currHeader, payload);
        pkt->setSequenceNum(currSeqNum);
        if (guaranteed) pkt->setGuaranteed();

        // erase consumed bytes
        readBuffer.erase(readBuffer.begin(), readBuffer.begin() + 4 + currPayloadLen);
    }
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

std::vector<std::shared_ptr<SongbirdCore::Packet>> SongbirdCore::reorderPackets()
{
    std::vector<std::shared_ptr<Packet>> dispatch;
    std::vector<std::pair<Remote, RemoteOrder>> needTimers;
    std::vector<TimerHandle_t> timersToStop;
    
    {
        SpinLockGuard guard(dataSpinlock);

        // Iterating through remotes
        for (auto itOrder = remoteOrders.begin(); itOrder != remoteOrders.end(); ++itOrder)
        {
            Remote r = itOrder->first;
            RemoteOrder& order = itOrder->second;

            auto remotePackets = reorderRemote(r, order, timersToStop);
            dispatch.insert(dispatch.end(), remotePackets.begin(), remotePackets.end());
            
            // Check if this remote needs a timer started
            if (order.needsTimerStart) {
                needTimers.push_back({r, order});
                order.needsTimerStart = false;
            }
        }
    }
    
    // Stop timers OUTSIDE the spinlock
    for (auto timer : timersToStop) {
        if (timer) {
            xTimerStop(timer, 0);
        }
    }
    
    // Start timers OUTSIDE the spinlock
    for (auto& pair : needTimers) {
        TimerHandle_t newTimer = startMissingTimer(pair.second);
        // Update the timer handle back in the map
        SpinLockGuard guard(dataSpinlock);
        auto it = remoteOrders.find(pair.first);
        if (it != remoteOrders.end()) {
            it->second.missingTimer = newTimer;
            it->second.missingTimerActive = true;
        }
    }

    return dispatch;
}

std::vector<std::shared_ptr<SongbirdCore::Packet>> SongbirdCore::reorderRemote(const SongbirdCore::Remote r, SongbirdCore::RemoteOrder& order, std::vector<TimerHandle_t>& timersToStop) {
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
                // Add timer to stop list instead of stopping directly
                timersToStop.push_back(order.missingTimer);
                order.missingTimerActive = false;
            }
            continue;
        }

        unsigned long nowMs = millis();

        // No packets with correct sequence, starting timeout
        if (!order.missingTimerActive)
        {
            // Set flag instead of calling timer functions directly (called from spinlock context)
            order.needsTimerStart = true;
            break;
        }

        break;
    }
    return dispatch;
}

TimerHandle_t SongbirdCore::startMissingTimer(RemoteOrder& order)
{
    // If timer already exists, just reset it to restart the period
    if (order.missingTimer) {
        xTimerReset(order.missingTimer, 0);
    } else {
        // Create new timer on first use
        // Allocate TimeoutID dynamically to ensure it remains valid for timer lifetime
        auto *id = static_cast<TimeoutID*>(pvPortMalloc(sizeof(TimeoutID)));
        id->owner = order.timeoutID.owner;
        id->remote = order.timeoutID.remote;
        
        TimerHandle_t handle = xTimerCreate(
            "missingTimer",
            pdMS_TO_TICKS(missingPacketTimeoutMs),
            pdFALSE, // one-shot
            (void *) id,
            missingTimerCallback
        );
        
        // Start the timer
        xTimerStart(handle, 0);
        order.missingTimer = handle;
    }
    
    // Mark timer as active
    order.missingTimerActive = true;
    
    return order.missingTimer;
}

void SongbirdCore::onMissingTimeout(const Remote remote) {
    std::vector<std::shared_ptr<Packet>> dispatch;
    std::vector<TimerHandle_t> timersToStop;
    TimerHandle_t timerToDelete = nullptr;
    bool needsReorder = false;
    
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
            needsReorder = true;
        } else {
            // No packets for this remote — delete it safely
            // Mark timer for deletion outside the lock
            if (order.missingTimer) {
                timerToDelete = order.missingTimer;
            }
            remoteOrders.erase(it);
            remoteMap.erase(remote);
        }
    }
    
    // Handle reordering outside the spinlock
    if (needsReorder) {
        SpinLockGuard guard(dataSpinlock);
        auto it = remoteOrders.find(remote);
        if (it != remoteOrders.end()) {
            dispatch = reorderRemote(remote, it->second, timersToStop);
        }
    }
    
    // Stop/delete timers OUTSIDE the spinlock
    for (auto timer : timersToStop) {
        if (timer) {
            xTimerStop(timer, 0);
        }
    }
    
    if (timerToDelete) {
        xTimerStop(timerToDelete, 0);
        // Free the TimeoutID allocated when timer was created
        auto *id = static_cast<TimeoutID*>(pvTimerGetTimerID(timerToDelete));
        vPortFree(id);
        xTimerDelete(timerToDelete, 0);
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

void SongbirdCore::updateRemoteOrder(std::shared_ptr<Packet> pkt) {
    Remote remote = pkt->getRemote();
    uint8_t seqNum = pkt->getSequenceNum();
    bool needsTimerStart = false;
    TimerHandle_t existingTimer = nullptr;
    TimeoutID timerContext;
    
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = remoteOrders.find(remote);
        if (it == remoteOrders.end()) {
            // First packet from this remote - initialize expectedSeqNum
            TimeoutID id{this, remote};
            RemoteOrder order = {seqNum, id};
            remoteOrders[remote] = order;
            it = remoteOrders.find(remote);
            
            // In ordering mode, we expect the next packet after this one
            // In allowOutOfOrder mode, same thing (for repeat detection)
            if (!allowOutofOrder) {
                // In ordering mode, start from this sequence number
                it->second.expectedSeqNum = seqNum;
            } else {
                // In allowOutOfOrder mode, expect the next sequence after this one
                it->second.expectedSeqNum = seqNum + 1;
                // Start timer for inactive remote cleanup
                needsTimerStart = true;
                timerContext = it->second.timeoutID;
            }
        } else {
            // Remote order already exists
            // Only update expectedSeqNum in allowOutOfOrder mode (for repeat detection)
            // In ordering mode, expectedSeqNum is managed by reorderRemote
            if (allowOutofOrder) {
                it->second.expectedSeqNum = seqNum + 1;
                // Restart timer to keep remote active
                existingTimer = it->second.missingTimer;
                needsTimerStart = true;
                timerContext = it->second.timeoutID;
            }
        }
    }
    
    // Start/restart timer OUTSIDE the spinlock
    if (needsTimerStart) {
        TimerHandle_t timer = nullptr;
        
        if (existingTimer) {
            // Reset existing timer
            xTimerReset(existingTimer, 0);
            timer = existingTimer;
        } else {
            // Create new timer
            auto *id = static_cast<TimeoutID*>(pvPortMalloc(sizeof(TimeoutID)));
            id->owner = timerContext.owner;
            id->remote = timerContext.remote;
            
            timer = xTimerCreate(
                "missingTimer",
                pdMS_TO_TICKS(missingPacketTimeoutMs),
                pdFALSE, // one-shot
                (void *) id,
                missingTimerCallback
            );
            
            xTimerStart(timer, 0);
        }
        
        // Update the timer handle back in the map
        SpinLockGuard guard(dataSpinlock);
        auto it = remoteOrders.find(remote);
        if (it != remoteOrders.end()) {
            it->second.missingTimer = timer;
            it->second.missingTimerActive = true;
        }
    }
}

bool SongbirdCore::isRepeatPacket(std::shared_ptr<Packet> pkt) {
    // Only check for repeat if guaranteed delivery is enabled
    if (!pkt->isGuaranteed()) return false;

    uint8_t seqNum = pkt->getSequenceNum();
    Remote remote = pkt->getRemote();
    
    SpinLockGuard guard(dataSpinlock);
    auto it = remoteOrders.find(remote);
    if (it != remoteOrders.end()) {
        uint8_t expectedSeq = it->second.expectedSeqNum;
        // Check if this sequence number is less than expected
        // Use signed 8-bit arithmetic to handle wraparound correctly
        int8_t diff = (int8_t)seqNum - (int8_t)expectedSeq;
        if (diff < 0 && diff > -128) {
            // This is a repeat packet (sequence is in the past)
            return true;
        }
    }
    return false;
}

bool SongbirdCore::checkForAck(std::shared_ptr<Packet> pkt) {
    // ACK handling and repeat detection only in UNRELIABLE mode
    if (reliableMode != UNRELIABLE) {
        return false; // No ACK handling in RELIABLE mode
    }
    
    // Check if this is an ACK packet (header 0x00)
    if (pkt->getHeader() == 0x00) {
        // This is an ACK packet - remove the acknowledged packet from retransmit queue
        uint8_t ackSeq = pkt->getSequenceNum();
        removeAcknowledgedPacket(ackSeq);
        return true; // ACK handled, don't dispatch to handlers
    }
    
    // Not an ACK packet - check if we need to send an ACK for this packet
    if (pkt->isGuaranteed()) {
        // Send ACK back to sender
        uint8_t seqNum = pkt->getSequenceNum();
        IPAddress remoteIP = pkt->getRemoteIP();
        uint16_t remotePort = pkt->getRemotePort();
        
        // Create ACK packet
        Packet ackPkt(0x00); // ACK header
        ackPkt.setRemote(remoteIP, remotePort);
        // Send ACK packet (even for repeats, in case the ACK was dropped)
        sendPacket(ackPkt, seqNum, false);
    }
    
    return isRepeatPacket(pkt); // Not an ACK, should be dispatched to handlers
}

void SongbirdCore::removeAcknowledgedPacket(uint8_t seqNum) {
    TimerHandle_t timerToStop = nullptr;
    void* timerID = nullptr;
    
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = outgoingGuaranteed.find(seqNum);
        if (it != outgoingGuaranteed.end()) {
            if (it->second.timer) {
                timerToStop = it->second.timer;
                timerID = pvTimerGetTimerID(timerToStop);
            }
            outgoingGuaranteed.erase(it);
        }
    }
    
    // Stop and delete timer OUTSIDE the spinlock
    if (timerToStop) {
        xTimerStop(timerToStop, 0);
        if (timerID) {
            vPortFree(timerID);
        }
        xTimerDelete(timerToStop, 0);
    }
}

void SongbirdCore::onRetransmitTimeout(uint8_t seqNum) {
    bool needsResend = false;
    OutgoingInfo info;
    TimerHandle_t timerToCleanup = nullptr;
    void* timerID = nullptr;
    
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = outgoingGuaranteed.find(seqNum);
        if (it != outgoingGuaranteed.end()) {
            info = it->second;
            
            // Check if we've exceeded max retransmit attempts (0 = infinite)
            if (maxRetransmitAttempts > 0 && info.retransmitCount >= maxRetransmitAttempts) {
                // Max attempts reached, clean up and stop retransmitting
                if (info.timer) {
                    timerToCleanup = info.timer;
                    timerID = pvTimerGetTimerID(info.timer);
                }
                outgoingGuaranteed.erase(it);
            } else {
                // Increment retransmit counter
                it->second.retransmitCount++;
                needsResend = true;
            }
        }
    }
    
    // Clean up timer OUTSIDE the spinlock
    if (timerToCleanup) {
        xTimerStop(timerToCleanup, 0);
        if (timerID) {
            vPortFree(timerID);
        }
        xTimerDelete(timerToCleanup, 0);
        return;
    }
    
    if (needsResend) {
        // Resend packet
        sendPacket(*info.pkt.get(), info.pkt->getSequenceNum(), false);
        // Restart the existing timer (don't create a new one)
        if (info.timer) {
            xTimerReset(info.timer, 0);
        }
    }
}

void SongbirdCore::flush() {
    {
        SpinLockGuard guard(dataSpinlock);
        readBuffer.clear();
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

void SongbirdCore::appendToReadBuffer(const uint8_t* data, std::size_t length) {
    SpinLockGuard guard(dataSpinlock);
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}

// Retransmit timer callback
static void retransmitTimerCallback(TimerHandle_t xTimer) {
    auto *ctx = static_cast<SongbirdCore::RetransmitID*>(pvTimerGetTimerID(xTimer));
    ctx->owner->onRetransmitTimeout(ctx->seq);
}

TimerHandle_t SongbirdCore::startRetransmitTimer(uint8_t seqNum) {
    // Prepare timer context
    auto *id = static_cast<RetransmitID*>(pvPortMalloc(sizeof(RetransmitID)));
    id->owner = this;
    id->seq = seqNum;
    TimerHandle_t handle = xTimerCreate(
        "retransmitTimer",
        pdMS_TO_TICKS(retransmitTimeoutMs),
        pdFALSE,
        (void*)id,
        retransmitTimerCallback
    );
    // Start the timer (no need for stop/change period on a freshly created timer)
    xTimerStart(handle, 0);
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = outgoingGuaranteed.find(seqNum);
        if (it != outgoingGuaranteed.end()) {
            it->second.timer = handle;
        }
    }
    return handle;
}