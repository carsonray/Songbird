#include "SongbirdCore.h"

#include <algorithm>
#include <cassert>
#include <cstdint>

using namespace std::chrono_literals;

/// Packet implementation
SongbirdCore::Packet::Packet(uint8_t header)
    : header(header), sequenceNum(0), guaranteedFlag(false), payloadLength(0), payload(), readPos(0) {
}

SongbirdCore::Packet::Packet(uint8_t header, const std::vector<uint8_t>& payload)
    : header(header), sequenceNum(0), guaranteedFlag(false), payloadLength(payload.size()), payload(payload), readPos(0) {
}

std::vector<uint8_t> SongbirdCore::Packet::toBytes(SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode) const {
    std::vector<uint8_t> out;

    if (reliableMode == SongbirdCore::RELIABLE) {
        // RELIABLE mode: no seq/guaranteed bytes
        // STREAM: [header][payload] (COBS encoded)
        // PACKET: [header][payload]
        out.reserve(1 + payloadLength);
        out.push_back(header);
    }
    else {
        // UNRELIABLE mode: includes seq/guaranteed bytes
        // STREAM: [header][seq][guaranteed][payload] (COBS encoded)
        // PACKET: [header][seq][guaranteed][payload]
        out.reserve(3 + payloadLength);
        out.push_back(header);
        out.push_back(sequenceNum);
        out.push_back(guaranteedFlag ? 1 : 0);
    }

    if (!payload.empty()) {
        out.insert(out.end(), payload.begin(), payload.end());
    }
    
    // Apply COBS encoding in STREAM mode
    if (mode == SongbirdCore::STREAM) {
        std::vector<uint8_t> encoded = SongbirdCore::cobsEncode(out.data(), out.size());
        encoded.push_back(0x00);  // Add delimiter
        return encoded;
    }
    
    return out;
}

void SongbirdCore::Packet::setSequenceNum(uint8_t seqNum) {
    sequenceNum = seqNum;
}

void SongbirdCore::Packet::setGuaranteed(bool guaranteed) {
    guaranteedFlag = guaranteed;
}

bool SongbirdCore::Packet::isGuaranteed() const {
    return guaranteedFlag;
}

uint8_t SongbirdCore::Packet::getHeader() const {
    return header;
}

uint8_t SongbirdCore::Packet::getSequenceNum() const {
    return static_cast<uint8_t>(sequenceNum);
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

void SongbirdCore::Packet::setRemote(const boost::asio::ip::address& ip, uint16_t port) {
    remoteIP = ip;
    remotePort = port;
}

void SongbirdCore::Packet::setRemote(const Remote& remote) {
    remoteIP = remote.ip;
    remotePort = remote.port;
}

SongbirdCore::Remote SongbirdCore::Packet::getRemote() const {
    Remote remote{ remoteIP, remotePort };
    return remote;
}

boost::asio::ip::address SongbirdCore::Packet::getRemoteIP() const {
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
        (static_cast<uint32_t>(buf[2]) << 8) |
        (static_cast<uint32_t>(buf[3]));
    float v;
    std::memcpy(&v, &bits, sizeof(float));
    return v;
}

int16_t SongbirdCore::Packet::readInt16() {
    uint8_t buf[2] = { 0,0 };
    readBytes(buf, 2);
    int16_t val = static_cast<int16_t>(static_cast<uint16_t>(buf[1]) | (static_cast<uint16_t>(buf[0]) << 8));
    return val;
}

/// SongbirdCore implementation

SongbirdCore::SongbirdCore(std::string name, SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode)
    : self(this), name(std::move(name)), processMode(mode), reliableMode(reliableMode), nextSeqNum(0), missingPacketTimeoutMs(100), retransmissionTimeoutMs(1000), maxRetransmitAttempts(5)
{
    // Start missing-packet monitor thread for desktop (also handles retransmission)
    missingTimerThreadStop.store(false);
    missingTimerThread = std::thread([this]() {
        using namespace std::chrono;
        while (!missingTimerThreadStop.load()) {
            // Sleep for a short interval, or until signalled
            std::unique_lock<std::mutex> lk(missingTimerMutex);
            missingTimerCv.wait_for(lk, std::chrono::milliseconds(std::min(missingPacketTimeoutMs, retransmissionTimeoutMs)), 
                [this]() { return missingTimerThreadStop.load(); });
            if (missingTimerThreadStop.load()) break;

            // Collect remotes whose missing timer expired
            std::vector<Remote> expiredRemotes;
            // Collect packets that need retransmission
            std::vector<uint8_t> retransmitPackets;
            
            auto now = steady_clock::now();
            {
                std::lock_guard<std::mutex> lock(dataMutex);
                // Check missing packet timeouts
                for (auto& it : remoteOrders) {
                    const Remote& r = it.first;
                    RemoteOrder& order = it.second;
                    if (order.missingTimerActive && order.missingTimerStart != std::chrono::steady_clock::time_point::min()) {
                        auto elapsed = duration_cast<milliseconds>(now - order.missingTimerStart).count();
                        if (static_cast<uint32_t>(elapsed) >= missingPacketTimeoutMs) {
                            expiredRemotes.push_back(r);
                        }
                    }
                }

                // Check guaranteed delivery retransmission timeouts
                for (auto& it : outgoingGuaranteed) {
                    uint8_t seqNum = it.first;
                    OutgoingInfo& gp = it.second;
                    auto elapsed = duration_cast<milliseconds>(now - gp.sendTime).count();
                    if (static_cast<uint32_t>(elapsed) >= retransmissionTimeoutMs) {
                        retransmitPackets.push_back(seqNum);
                    }
                }
            }

            // Call onMissingTimeout for each expired remote outside the data lock
            for (const auto& r : expiredRemotes) {
                onMissingTimeout(r);
            }

            // Retransmit guaranteed packets
            for (auto& seqNum : retransmitPackets) {
				onRetransmissionTimeout(seqNum);
            }
        }
    });
}

SongbirdCore::~SongbirdCore() {
    // Stop monitor thread
    missingTimerThreadStop.store(true);
    missingTimerCv.notify_all();
    if (missingTimerThread.joinable()) missingTimerThread.join();
}

void SongbirdCore::attachStream(IStream* stream) {
    this->stream = stream;
}

void SongbirdCore::setReadHandler(ReadHandler handler) {
    std::lock_guard<std::mutex> lock(dataMutex);
    readHandler = std::move(handler);
}

void SongbirdCore::setHeaderHandler(uint8_t header, ReadHandler handler) {
    // Header 0x00 is reserved for ACKs
    if (header == 0x00) {
        std::cerr << "Header 0x00 is reserved for ACKs and cannot be used\n";
        return;
    }
    std::lock_guard<std::mutex> lock(dataMutex);
    headerHandlers[header] = std::move(handler);
}

void SongbirdCore::clearHeaderHandler(uint8_t header) {
    std::lock_guard<std::mutex> lock(dataMutex);
    headerHandlers.erase(header);
    headerMap.erase(header);
}

void SongbirdCore::setRemoteHandler(boost::asio::ip::address remoteIP, uint16_t remotePort, ReadHandler handler) {
    std::lock_guard<std::mutex> lock(dataMutex);
    Remote remote{ remoteIP, remotePort };
    remoteHandlers[remote] = std::move(handler);
}

void SongbirdCore::clearRemoteHandler(boost::asio::ip::address remoteIP, uint16_t remotePort) {
    std::lock_guard<std::mutex> lock(dataMutex);
    Remote remote{ remoteIP, remotePort };
    remoteHandlers.erase(remote);
    remoteMap.erase(remote);
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::waitForHeader(uint8_t header, uint32_t timeoutMs) {
    // First check if packet already present
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        auto it = headerMap.find(header);
        if (it != headerMap.end()) {
            auto pkt = it->second;
            headerMap.erase(it);
            return pkt;
        }
    }

    // Not present: register waiter object and wait on its own cv
    auto waiter = std::make_shared<Waiter>();
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        headerWaiters[header].push_back(waiter);
    }

    std::unique_lock<std::mutex> lk(waiter->mtx);
    bool got = waiter->cv.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&]() {
        return waiter->signalled.load();
    });

    // unregister waiter
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        auto &vec = headerWaiters[header];
        vec.erase(std::remove(vec.begin(), vec.end(), waiter), vec.end());
        if (vec.empty()) headerWaiters.erase(header);
    }

    if (!got) return nullptr;

    std::lock_guard<std::mutex> lock3(dataMutex);
    auto pkt = headerMap[header];
    headerMap.erase(header);
    return pkt;
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::waitForRemote(boost::asio::ip::address remoteIP, uint16_t remotePort, uint32_t timeoutMs) {
    Remote remote{ remoteIP, remotePort };
    // First check if packet already present
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        auto it = remoteMap.find(remote);
        if (it != remoteMap.end()) {
            auto pkt = it->second;
            remoteMap.erase(it);
            return pkt;
        }
    }

    // Not present: register waiter object and wait on its own cv
    auto waiter = std::make_shared<Waiter>();
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        remoteWaiters[remote].push_back(waiter);
    }

    std::unique_lock<std::mutex> lk(waiter->mtx);
    bool got = waiter->cv.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&]() {
        std::lock_guard<std::mutex> lock(dataMutex);
        return waiter->signalled.load();
    });

    // unregister waiter
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        auto &vec = remoteWaiters[remote];
        vec.erase(std::remove(vec.begin(), vec.end(), waiter), vec.end());
        if (vec.empty()) remoteWaiters.erase(remote);
    }

    if (!got) return nullptr;

    std::lock_guard<std::mutex> lock3(dataMutex);
    auto pkt = remoteMap[remote];
    remoteMap.erase(remote);
    return pkt;
}

SongbirdCore::Packet SongbirdCore::createPacket(uint8_t header) {
    // Header 0x00 is reserved for ACKs
    if (header == 0x00) {
        std::cerr << "Header 0x00 is reserved for ACKs and cannot be used\n";
        return Packet(0x01); // Return packet with header 0x01 instead
    }
    return Packet(header);
}

void SongbirdCore::setMissingPacketTimeout(uint32_t ms) {
    std::lock_guard<std::mutex> lock(dataMutex);
    missingPacketTimeoutMs = ms;
    // notify monitor thread in case it needs to re-evaluate
    missingTimerCv.notify_all();
}

void SongbirdCore::setRetransmissionTimeout(uint32_t ms) {
    std::lock_guard<std::mutex> lock(dataMutex);
    retransmissionTimeoutMs = ms;
    // notify monitor thread in case it needs to re-evaluate
    missingTimerCv.notify_all();
}

void SongbirdCore::setMaxRetransmitAttempts(uint32_t attempts) {
    std::lock_guard<std::mutex> lock(dataMutex);
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
		std::cerr << "Stream not attached or not open, cannot send packet\n";
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
    }
    else {
        stream->write(bytes.data(), bytes.size());
    }

    // Track guaranteed packets and start retransmit timer in both modes
    if (guaranteeDelivery && reliableMode == UNRELIABLE) {
        Remote remote = packet.getRemote();
        // If packet doesn't have a valid remote, use the stream's default remote
        if (supportsRemote && remote.port == 0) {
            boost::asio::ip::address defaultIP;
            uint16_t defaultPort;
            if (stream->getDefaultRemote(defaultIP, defaultPort)) {
                remote.ip = defaultIP;
                remote.port = defaultPort;
                packet.setRemote(remote);
            }
        }
		// Initialize outgoing info with current time
		OutgoingInfo info;
		info.sendTime = std::chrono::steady_clock::now();
		info.packet = std::make_shared<Packet>(packet);
		info.remote = remote;

        {
			std::lock_guard<std::mutex> lock(dataMutex);
            outgoingGuaranteed[sequenceNum] = info;
        }
    }
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length) {
    parseData(data, length, boost::asio::ip::address(), 0);
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length, boost::asio::ip::address remoteIP, uint16_t remotePort) {
    if (processMode == PACKET) {
        // Parses full packet
        auto pkt = packetFromData(data, length);
        if (!pkt) return;
        pkt->setRemote(remoteIP, remotePort);

        // Check for ACK and handle guaranteed delivery before buffering/dispatching
        // This ensures ACKs are sent immediately even if packet gets bufffered as out-of-order
        if (checkForAck(pkt)) {
            return; // Was an ACK packet, already handled
        }

        std::vector<std::shared_ptr<Packet>> dispatch;
        if (allowOutofOrder || reliableMode == RELIABLE) {
            dispatch.push_back(pkt);
            if (reliableMode == UNRELIABLE) {
                if (pkt->isGuaranteed()) {
                    // Update remoteOrders even in out-of-order mode for repeat detection (UNRELIABLE mode only)
                    updateRemoteOrder(pkt);
                }
				std::lock_guard<std::mutex> lock(dataMutex);
                // If any remaining packets in incoming packets add to dispatch
                for (const auto& p : incomingPackets) {
                    dispatch.push_back(p.second);
                }
                incomingPackets.clear();
            }
        }
        else if (reliableMode == UNRELIABLE) {
            // If it is a new remote and ordering mode is on, add to remote order map
            updateRemoteOrder(pkt);

            {
				std::lock_guard<std::mutex> lock(dataMutex);

                const RemoteExpected expected{ pkt->getRemote(), pkt->getSequenceNum() };
                incomingPackets[expected] = pkt;
            }

            dispatch = reorderPackets();
        }

        // Call handlers on dispatched packets
        for (auto& p : dispatch) {
            callHandlers(p);
        }
    }
    else if (processMode == STREAM) {
        // Adds data to readBuffer
        appendToReadBuffer(data, length);
        // Process COBS-encoded packets in readBuffer
        while (true) {
            std::shared_ptr<Packet> pkt = packetFromStreamCOBS();
            if (!pkt) {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - lastDataTimeMs > missingPacketTimeoutMs) {
                    // Timeout: clear read buffer to avoid stale data
                    flush();
                }
                break;
            }
            lastDataTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
            pkt->setRemote(remoteIP, remotePort);

            // Check for ACK and handle guaranteed delivery
            if (checkForAck(pkt)) {
                continue; // Was an ACK packet, skip to next packet
            }

            // Updates remote order for UNRELIABLE mode
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
    }
    else {
        // UNRELIABLE mode: [header][seq][guaranteed][payload]
        if (length < 3) return pkt;
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

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::packetFromStreamCOBS() {
    std::lock_guard<std::mutex> lock(dataMutex);
    std::shared_ptr<SongbirdCore::Packet> pkt;
    
    // Look for 0x00 delimiter
    auto it = std::find(readBuffer.begin(), readBuffer.end(), 0x00);
    if (it == readBuffer.end()) {
        // No complete packet yet
        return pkt;
    }
    
    std::size_t delimiter_idx = std::distance(readBuffer.begin(), it);
    
    // Extract and decode COBS packet
    if (delimiter_idx == 0) {
        // Empty packet, skip delimiter
        readBuffer.erase(readBuffer.begin());
        return pkt;
    }
    
    std::vector<uint8_t> decoded = cobsDecode(readBuffer.data(), delimiter_idx);
    readBuffer.erase(readBuffer.begin(), readBuffer.begin() + delimiter_idx + 1); // Remove packet + delimiter
    
    if (decoded.empty()) {
        return pkt;
    }
    
    // Parse decoded packet
    if (reliableMode == RELIABLE) {
        // RELIABLE: [header][payload]
        if (decoded.size() < 1) return pkt;
        uint8_t currHeader = decoded[0];
        std::vector<uint8_t> payload;
        if (decoded.size() > 1) {
            payload.insert(payload.end(), decoded.begin() + 1, decoded.end());
        }
        pkt = std::make_shared<Packet>(currHeader, payload);
    } else {
        // UNRELIABLE: [header][seq][guaranteed][payload]
        if (decoded.size() < 3) return pkt;
        uint8_t currHeader = decoded[0];
        uint8_t currSeqNum = decoded[1];
        uint8_t guaranteed = decoded[2];
        std::vector<uint8_t> payload;
        if (decoded.size() > 3) {
            payload.insert(payload.end(), decoded.begin() + 3, decoded.end());
        }
        pkt = std::make_shared<Packet>(currHeader, payload);
        pkt->setSequenceNum(currSeqNum);
        if (guaranteed) pkt->setGuaranteed();
    }
    
    return pkt;
}

std::vector<uint8_t> SongbirdCore::cobsEncode(const uint8_t* data, std::size_t length) {
    if (length == 0) return std::vector<uint8_t>();
    
    std::vector<uint8_t> encoded;
    encoded.reserve(length + (length / 254) + 1);
    
    std::size_t code_idx = 0;
    uint8_t code = 0x01;
    
    encoded.push_back(0); // Placeholder for first code
    
    for (std::size_t i = 0; i < length; i++) {
        if (data[i] == 0x00) {
            encoded[code_idx] = code;
            code_idx = encoded.size();
            encoded.push_back(0); // Placeholder for next code
            code = 0x01;
        } else {
            encoded.push_back(data[i]);
            code++;
            if (code == 0xFF) {
                encoded[code_idx] = code;
                code_idx = encoded.size();
                encoded.push_back(0); // Placeholder for next code
                code = 0x01;
            }
        }
    }
    
    encoded[code_idx] = code;
    return encoded;
}

std::vector<uint8_t> SongbirdCore::cobsDecode(const uint8_t* data, std::size_t length) {
    if (length == 0) return std::vector<uint8_t>();
    
    std::vector<uint8_t> decoded;
    decoded.reserve(length);
    
    std::size_t i = 0;
    while (i < length) {
        uint8_t code = data[i++];
        
        for (uint8_t j = 1; j < code && i < length; j++) {
            decoded.push_back(data[i++]);
        }
        
        if (code < 0xFF && i < length) {
            decoded.push_back(0x00);
        }
    }
    
    return decoded;
}

void SongbirdCore::callHandlers(std::shared_ptr<Packet> pkt) {
    uint8_t header = pkt->getHeader();
    Remote remote = pkt->getRemote();
    // Lookup and store handlers under locks, but invoke them outside locks
    ReadHandler headerHandler = nullptr;
    ReadHandler remoteHandler = nullptr;
    ReadHandler globalHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(dataMutex);

        auto it = headerHandlers.find(header);
        if (it != headerHandlers.end()) headerHandler = it->second;
        // update header map (single latest packet)
        headerMap[header] = pkt;

        auto it2 = remoteHandlers.find(remote);
        if (it2 != remoteHandlers.end()) remoteHandler = it2->second;
        // update last remote map
        remoteMap[remote] = pkt;

        globalHandler = readHandler;
    }

    // Notify one specific waiter (if any) for header and remote
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        auto hit = headerWaiters.find(header);
        if (hit != headerWaiters.end() && !hit->second.empty()) {
            // notify the first registered waiter for this header
            std::shared_ptr<Waiter> waiter = hit->second.front();
            {
                std::lock_guard<std::mutex> lk(waiter->mtx);
                waiter->signalled.store(true);
                waiter->cv.notify_one();
            }
        }
        auto rit = remoteWaiters.find(remote);
        if (rit != remoteWaiters.end() && !rit->second.empty()) {
            std::shared_ptr<Waiter> waiter = rit->second.front();
            {
                std::lock_guard<std::mutex> lk(waiter->mtx);
                waiter->signalled.store(true);
                waiter->cv.notify_one();
            }
        }
    }

    if (headerHandler) headerHandler(pkt);
    if (remoteHandler) remoteHandler(pkt);
    if (globalHandler) globalHandler(pkt);
}

std::vector<std::shared_ptr<SongbirdCore::Packet>> SongbirdCore::reorderPackets()
{
    std::lock_guard<std::mutex> lock(dataMutex);
    std::vector<std::shared_ptr<Packet>> dispatch;

    // Iterating through remotes
    for (auto itOrder = remoteOrders.begin(); itOrder != remoteOrders.end(); ++itOrder)
    {
        Remote r = itOrder->first;
        RemoteOrder& order = itOrder->second;

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
                // Cancel desktop timer
                order.missingTimerActive = false;
                order.missingTimerStart = std::chrono::steady_clock::time_point::min();
            }
            continue;
        }

        // No packets with correct sequence, starting timeout
        if (!order.missingTimerActive)
        {
            order.missingTimerActive = true;
            order.missingTimerStart = std::chrono::steady_clock::now();
            // Notify timer thread to re-evaluate
            missingTimerCv.notify_all();
            break;
        }

        break;
    }
    return dispatch;
}

void SongbirdCore::onMissingTimeout(const Remote remote) {
    std::vector<std::shared_ptr<Packet>> dispatch;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        // Timeout: find nearest forward seqNum for this remote
        bool found = false;
        uint8_t bestDist = 0xFF;
        uint8_t bestSeq = 0;

        // Finds remote order from map
        auto it = remoteOrders.find(remote);
        if (it == remoteOrders.end()) return;
        RemoteOrder& order = it->second;

        for (auto& p : incomingPackets)
        {
            if (!(p.first.remote == remote)) continue;

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
        }
        else {
            // No packets for this remote, delete it safely
            remoteOrders.erase(it);
            remoteMap.erase(remote);
        }
    }

    // Call handlers on dispatched packets
    for (auto& p : dispatch) {
        callHandlers(p);
    }
}

void SongbirdCore::updateRemoteOrder(std::shared_ptr<Packet> pkt) {
    std::lock_guard<std::mutex> lock(dataMutex);
    Remote remote = pkt->getRemote();
    uint8_t seqNum = pkt->getSequenceNum();

    auto it = remoteOrders.find(remote);
    if (it == remoteOrders.end()) {
        // First packet - initialize order
        RemoteOrder order = { seqNum };
        remoteOrders[remote] = order;
        it = remoteOrders.find(remote); // Update iterator to point to the newly inserted entry

        if (!allowOutofOrder) {
            // In ordering mode, start from this sequence
            it->second.expectedSeqNum = seqNum;
        }
        else {
            // In allowOutOfOrder mode, expect next after this
            it->second.expectedSeqNum = seqNum + 1;
        }
    }
    else {
        // Only update expectedSeqNum in allowOutOfOrder mode
        // In ordering mode, reorderRemote manages it
        if (allowOutofOrder) {
            it->second.expectedSeqNum = seqNum + 1;
        }
    }

    if (allowOutofOrder) {
        // Restart missing timer to clean up inactive remotes (even in allowOutOfOrder mode)
        it->second.missingTimerActive = true;
        it->second.missingTimerStart = std::chrono::steady_clock::now();
        // Notify timer thread to re-evaluate
        missingTimerCv.notify_all();
    }
}

bool SongbirdCore::isRepeatPacket(std::shared_ptr<Packet> pkt) {
	// Only check for repeat if guaranteed delivery is enabled
	if (!pkt->isGuaranteed()) return false;

    uint8_t seqNum = pkt->getSequenceNum();
    Remote remote = pkt->getRemote();

    std::lock_guard<std::mutex> lock(dataMutex);
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
        // Send ACK back to sender (even for repeats, in case original ACK was dropped)
        uint8_t seqNum = pkt->getSequenceNum();
        boost::asio::ip::address remoteIP = pkt->getRemoteIP();
        uint16_t remotePort = pkt->getRemotePort();
        
        // Create ACK packet
        Packet ackPkt(0x00); // ACK header
        ackPkt.setRemote(remoteIP, remotePort);
        // Send ACK packet
        sendPacket(ackPkt, seqNum, false);
    }

    // Return true if it's a repeat (don't dispatch to handlers)
    return isRepeatPacket(pkt);
}

void SongbirdCore::removeAcknowledgedPacket(uint8_t seqNum) {
    std::lock_guard<std::mutex> lock(dataMutex);
    auto it = outgoingGuaranteed.find(seqNum);
    if (it != outgoingGuaranteed.end()) {
		// Log acknowledgement with number of retransmits
        outgoingGuaranteed.erase(it);
    }
}

void SongbirdCore::onRetransmissionTimeout(uint8_t seqNum) {
    bool needsResend = false;
    OutgoingInfo info;
    {
		std::lock_guard<std::mutex> lock(dataMutex);
        auto it = outgoingGuaranteed.find(seqNum);
        if (it != outgoingGuaranteed.end()) {
            // Copy info before potentially erasing
            info = it->second;
            
            // Check if max retransmit attempts reached (0 means infinite retries)
            if (maxRetransmitAttempts > 0 && it->second.retransmitCount >= maxRetransmitAttempts) {
                // Remove from tracking after max attempts
                outgoingGuaranteed.erase(it);
            } else {
                needsResend = true;
                // Increment retransmit counter
                it->second.retransmitCount++;
                // Update send time
                it->second.sendTime = std::chrono::steady_clock::now();
            }
        }
    }

    if (needsResend) {
        // Resend packet
        sendPacket(*info.packet.get(), info.packet->getSequenceNum(), false);
    }
}



void SongbirdCore::flush() {
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        readBuffer.clear();
        incomingPackets.clear();
        headerMap.clear();
        newPacket = true;
    }
}

std::size_t SongbirdCore::getReadBufferSize() {
    std::lock_guard<std::mutex> lock(dataMutex);
    return readBuffer.size();
}

std::size_t SongbirdCore::getNumIncomingPackets() {
    std::lock_guard<std::mutex> lock(dataMutex);
    return incomingPackets.size();
}

void SongbirdCore::appendToReadBuffer(const uint8_t* data, std::size_t length) {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}