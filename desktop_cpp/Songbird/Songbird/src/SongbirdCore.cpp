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

SongbirdCore::Packet::Packet(uint8_t header, const std::vector<uint8_t>& payload, bool checksumOk)
    : header(header), sequenceNum(0), guaranteedFlag(false), checksumOk(checksumOk), payloadLength(payload.size()), payload(payload), readPos(0) {
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
        // STREAM: [header][seq][guaranteed][payload][checksum] (COBS encoded)
        // PACKET: [header][seq][guaranteed][payload][checksum]
        out.reserve(4 + payloadLength);
        out.push_back(header);
        out.push_back(sequenceNum);
        out.push_back(guaranteedFlag ? 1 : 0);
    }

    if (!payload.empty()) {
        out.insert(out.end(), payload.begin(), payload.end());
    }

    if (reliableMode == SongbirdCore::UNRELIABLE) {
        uint8_t checksum = 0;
        for (uint8_t byte : out) checksum ^= byte;
        out.push_back(checksum);
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

bool SongbirdCore::Packet::isChecksumValid() const {
    return checksumOk;
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

void SongbirdCore::Packet::setEndpoint(const IStream::Endpoint& value) {
    endpoint = value;
}

IStream::Endpoint SongbirdCore::Packet::getEndpoint() const {
    return endpoint;
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

void SongbirdCore::Packet::writeString(const std::string& str) {
    // Write length as uint16_t (big-endian)
    uint16_t len = static_cast<uint16_t>(str.length());
    writeByte(static_cast<uint8_t>((len >> 8) & 0xFF));
    writeByte(static_cast<uint8_t>(len & 0xFF));
    // Write string bytes
    writeBytes(reinterpret_cast<const uint8_t*>(str.c_str()), str.length());
}

std::string SongbirdCore::Packet::readString() {
    // Read length (uint16_t, big-endian)
    uint8_t lenBuf[2];
    readBytes(lenBuf, 2);
    uint16_t len = (static_cast<uint16_t>(lenBuf[0]) << 8) | static_cast<uint16_t>(lenBuf[1]);
    
    // Read string bytes
    if (len == 0) return std::string();
    
    std::vector<uint8_t> strBuf(len);
    readBytes(strBuf.data(), len);
    return std::string(strBuf.begin(), strBuf.end());
}

void SongbirdCore::Packet::writeProtobuf(const uint8_t* buffer, std::size_t length) {
    // Write length as uint16_t (big-endian)
    uint16_t len = static_cast<uint16_t>(length);
    writeByte(static_cast<uint8_t>((len >> 8) & 0xFF));
    writeByte(static_cast<uint8_t>(len & 0xFF));
    // Write protobuf bytes
    writeBytes(buffer, length);
}

void SongbirdCore::Packet::writeProtobuf(const std::vector<uint8_t>& data) {
    writeProtobuf(data.data(), data.size());
}

std::vector<uint8_t> SongbirdCore::Packet::readProtobuf() {
    // Read length (uint16_t, big-endian)
    uint8_t lenBuf[2];
    readBytes(lenBuf, 2);
    uint16_t len = (static_cast<uint16_t>(lenBuf[0]) << 8) | static_cast<uint16_t>(lenBuf[1]);
    
    // Read protobuf bytes
    if (len == 0) return std::vector<uint8_t>();
    
    std::vector<uint8_t> data(len);
    readBytes(data.data(), len);
    return data;
}

/// SongbirdCore implementation

SongbirdCore::SongbirdCore(std::string name, SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode)
    : self(this), name(std::move(name)), processMode(mode), reliableMode(reliableMode), nextSeqNum(0), missingPacketTimeoutMs(100), retransmissionTimeoutMs(1000), maxRetransmitAttempts(5)
{
    // Start retransmission monitor thread for desktop.
    missingTimerThreadStop.store(false);
    missingTimerThread = std::thread([this]() {
        using namespace std::chrono;
        while (!missingTimerThreadStop.load()) {
            std::unique_lock<std::mutex> lk(missingTimerMutex);
            missingTimerCv.wait_for(lk, std::chrono::milliseconds(std::min(missingPacketTimeoutMs, retransmissionTimeoutMs)),
                [this]() { return missingTimerThreadStop.load(); });
            if (missingTimerThreadStop.load()) break;

            auto now = steady_clock::now();
            std::vector<IStream::Endpoint> expiredEndpoints;
            std::vector<uint8_t> retransmitPackets;
            {
                std::lock_guard<std::mutex> lock(dataMutex);
                for (auto& it : endpointOrders) {
                    EndpointOrder& order = it.second;
                    if (order.missingTimerActive && order.missingTimerStart != steady_clock::time_point::min() &&
                        duration_cast<milliseconds>(now - order.missingTimerStart).count() >= missingPacketTimeoutMs) {
                        expiredEndpoints.push_back(it.first);
                    }
                }
                for (auto& it : outgoingGuaranteed) {
                    uint8_t seqNum = it.first;
                    OutgoingInfo& gp = it.second;
                    auto elapsed = duration_cast<milliseconds>(now - gp.sendTime).count();
                    if (static_cast<uint32_t>(elapsed) >= retransmissionTimeoutMs) {
                        retransmitPackets.push_back(seqNum);
                    }
                }
            }

            if (!expiredEndpoints.empty()) {
                std::lock_guard<std::mutex> lock(dataMutex);
                for (const IStream::Endpoint& endpoint : expiredEndpoints) {
                    endpointOrders.erase(endpoint);
                    endpointMap.erase(endpoint);
                }
            }

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

void SongbirdCore::setLogging(const Logging& value) {
    std::lock_guard<std::mutex> lock(dataMutex);
    logging = value;
    headerLogTracks.clear();
    endpointLogTracks.clear();
    logRateWindowStart = std::chrono::steady_clock::now();
}

bool SongbirdCore::loggingMatches(const IStream::Endpoint& endpoint, uint8_t header) const {
    return (!logging.filterEndpoint || endpoint == logging.endpoint) &&
           (!logging.filterHeader || header == logging.header);
}

const char* SongbirdCore::logEventName(LogEvent event) {
    switch (event) {
    case LOG_DROPPED: return "DROPPED";
    case LOG_RETRANSMITTED: return "RETRANSMITTED";
    case LOG_SENT: return "SENT";
    case LOG_RECEIVED: return "RECEIVED";
    default: return "UNKNOWN";
    }
}

std::string SongbirdCore::endpointString(const IStream::Endpoint& endpoint) {
    return endpoint.toString();
}

void SongbirdCore::logPacket(LogEvent event, const Packet& packet, const char* reason) {
    bool shouldLog = false;
    bool rateEnabled = false;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        if (!loggingMatches(packet.getEndpoint(), packet.getHeader())) return;

        LogTrack& headerTrack = headerLogTracks[packet.getHeader()];
        LogTrack& endpointTrack = endpointLogTracks[packet.getEndpoint()];
        if (event == LOG_SENT) {
            ++headerTrack.sent;
            ++endpointTrack.sent;
        } else if (event == LOG_RECEIVED) {
            ++headerTrack.received;
            ++endpointTrack.received;
        }

        shouldLog = logging.events & event;
        rateEnabled = logging.events & LOG_RATE;
        if (shouldLog) {
            std::cerr << "[" << name << "] " << logEventName(event)
                      << " header=" << static_cast<unsigned>(packet.getHeader())
                      << " seq=" << static_cast<unsigned>(packet.getSequenceNum())
                      << " guaranteed=" << (packet.isGuaranteed() ? 1 : 0)
                      << " payload=" << packet.getPayloadLength()
                      << " endpoint=" << endpointString(packet.getEndpoint());
            if (reason) std::cerr << " reason=" << reason;
            std::cerr << "\n";
        }
    }
    if (shouldLog || rateEnabled) logRatesIfDue();
}

void SongbirdCore::logTimeout(const IStream::Endpoint& endpoint) {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (!(logging.events & LOG_DROPPED) ||
        (logging.filterEndpoint && !(endpoint == logging.endpoint)) || logging.filterHeader) return;
    std::cerr << "[" << name << "] DROPPED header=? seq=? guaranteed=? payload=? endpoint="
              << endpointString(endpoint) << " reason=timeout\n";
}

void SongbirdCore::logRatesIfDue() {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (!(logging.events & LOG_RATE) || logging.rateIntervalMs == 0) return;
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - logRateWindowStart).count();
    if (elapsed < logging.rateIntervalMs) return;
    double seconds = elapsed / 1000.0;
    for (const auto& entry : headerLogTracks) {
        std::cerr << "[" << name << "] RATE header=" << static_cast<unsigned>(entry.first)
                  << " sent=" << entry.second.sent << " received=" << entry.second.received
                  << " pps=" << ((entry.second.sent + entry.second.received) / seconds) << "\n";
    }
    for (const auto& entry : endpointLogTracks) {
        std::cerr << "[" << name << "] RATE endpoint=" << endpointString(entry.first)
                  << " sent=" << entry.second.sent << " received=" << entry.second.received
                  << " pps=" << ((entry.second.sent + entry.second.received) / seconds) << "\n";
    }
    headerLogTracks.clear();
    endpointLogTracks.clear();
    logRateWindowStart = std::chrono::steady_clock::now();
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

void SongbirdCore::setEndpointHandler(const IStream::Endpoint& endpoint, ReadHandler handler) {
    std::lock_guard<std::mutex> lock(dataMutex);
    endpointHandlers[endpoint] = std::move(handler);
}

void SongbirdCore::clearEndpointHandler(const IStream::Endpoint& endpoint) {
    std::lock_guard<std::mutex> lock(dataMutex);
    endpointHandlers.erase(endpoint);
    endpointMap.erase(endpoint);
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

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::waitForEndpoint(const IStream::Endpoint& endpoint, uint32_t timeoutMs) {
    // First check if packet already present
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        auto it = endpointMap.find(endpoint);
        if (it != endpointMap.end()) {
            auto pkt = it->second;
            endpointMap.erase(it);
            return pkt;
        }
    }

    // Not present: register waiter object and wait on its own cv
    auto waiter = std::make_shared<Waiter>();
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        endpointWaiters[endpoint].push_back(waiter);
    }

    std::unique_lock<std::mutex> lk(waiter->mtx);
    bool got = waiter->cv.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&]() {
        std::lock_guard<std::mutex> lock(dataMutex);
        return waiter->signalled.load();
    });

    // unregister waiter
    {
        std::lock_guard<std::mutex> wlock(waitMutex);
        auto &vec = endpointWaiters[endpoint];
        vec.erase(std::remove(vec.begin(), vec.end(), waiter), vec.end());
        if (vec.empty()) endpointWaiters.erase(endpoint);
    }

    if (!got) return nullptr;

    std::lock_guard<std::mutex> lock3(dataMutex);
    auto pkt = endpointMap[endpoint];
    endpointMap.erase(endpoint);
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
    IStream::Endpoint endpoint = packet.getEndpoint();
    if (endpoint == IStream::Endpoint{}) {
        endpoint = stream->getEndpoint();
        packet.setEndpoint(endpoint);
    }
    stream->write(bytes.data(), bytes.size(), endpoint);
    logPacket(LOG_SENT, packet);

    // Track guaranteed packets and start retransmit timer in both modes
    if (guaranteeDelivery && reliableMode == UNRELIABLE) {
		// Initialize outgoing info with current time
		OutgoingInfo info;
		info.sendTime = std::chrono::steady_clock::now();
		info.packet = std::make_shared<Packet>(packet);
		info.endpoint = packet.getEndpoint();

        {
			std::lock_guard<std::mutex> lock(dataMutex);
            outgoingGuaranteed[sequenceNum] = info;
        }
    }
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length) {
    parseData(data, length, IStream::Endpoint{});
}

void SongbirdCore::parseData(const uint8_t* data, std::size_t length, const IStream::Endpoint& endpoint) {
    if (processMode == PACKET) {
        // Parses full packet
        auto pkt = packetFromData(data, length);
        if (!pkt) return;
        pkt->setEndpoint(endpoint);

        if (!pkt->isChecksumValid()) {
            logPacket(LOG_DROPPED, *pkt, "checksum");
            if (pkt->isGuaranteed()) {
                Packet nackPkt(ACK_HEADER);
                nackPkt.setEndpoint(endpoint);
                nackPkt.writeByte(NACK_CODE);
                sendPacket(nackPkt, pkt->getSequenceNum(), false);
            }
            return;
        }
        logPacket(LOG_RECEIVED, *pkt);

        // Check for ACK and handle guaranteed delivery before buffering/dispatching
        // This ensures ACKs are sent immediately even if packet gets bufffered as out-of-order
        if (checkForAck(pkt)) {
            return; // Was an ACK packet, already handled
        }

        std::vector<std::shared_ptr<Packet>> dispatch{ pkt };
        if (reliableMode == UNRELIABLE && pkt->isGuaranteed()) {
            updateEndpointOrder(pkt);
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
                    logTimeout(endpoint);
                    flush();
                }
                break;
            }
            lastDataTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
            pkt->setEndpoint(endpoint);

            if (!pkt->isChecksumValid()) {
                logPacket(LOG_DROPPED, *pkt, "checksum");
                if (pkt->isGuaranteed()) {
                    Packet nackPkt(ACK_HEADER);
                    nackPkt.setEndpoint(endpoint);
                    nackPkt.writeByte(NACK_CODE);
                    sendPacket(nackPkt, pkt->getSequenceNum(), false);
                }
                continue;
            }
            logPacket(LOG_RECEIVED, *pkt);

            // Check for ACK and handle guaranteed delivery
            if (checkForAck(pkt)) {
                continue; // Was an ACK packet, skip to next packet
            }

            // Updates remote order for UNRELIABLE mode
            if (reliableMode == UNRELIABLE) {
                updateEndpointOrder(pkt);
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
        // UNRELIABLE mode: [header][seq][guaranteed][payload][checksum]
        if (length < 3) return pkt;
        uint8_t currHeader = data[0];
        uint8_t currSeqNum = data[1];
        // For packet mode, third byte may be guaranteed flag
        size_t payloadOffset = 3;
        uint8_t guaranteed = data[2];
        uint8_t checksum = 0;
        for (size_t i = 0; i + 1 < length; ++i) checksum ^= data[i];
        bool checksumValid = length >= 4 && checksum == data[length - 1];
        // payload excludes the trailing checksum
        std::vector<uint8_t> payload;
        if (length > payloadOffset + 1) {
            payload.insert(payload.end(), data + payloadOffset, data + length - 1);
        }
        pkt = std::make_shared<Packet>(currHeader, payload, checksumValid);
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
        // UNRELIABLE: [header][seq][guaranteed][payload][checksum]
        if (decoded.size() < 3) return pkt;
        uint8_t currHeader = decoded[0];
        uint8_t currSeqNum = decoded[1];
        uint8_t guaranteed = decoded[2];
        std::vector<uint8_t> payload;
        uint8_t checksum = 0;
        for (size_t i = 0; i + 1 < decoded.size(); ++i) checksum ^= decoded[i];
        bool checksumValid = decoded.size() >= 4 && checksum == decoded.back();
        if (decoded.size() > 4) {
            payload.insert(payload.end(), decoded.begin() + 3, decoded.end() - 1);
        }
        pkt = std::make_shared<Packet>(currHeader, payload, checksumValid);
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
    IStream::Endpoint endpoint = pkt->getEndpoint();
    // Lookup and store handlers under locks, but invoke them outside locks
    ReadHandler headerHandler = nullptr;
    ReadHandler endpointHandler = nullptr;
    ReadHandler globalHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(dataMutex);

        auto it = headerHandlers.find(header);
        if (it != headerHandlers.end()) headerHandler = it->second;
        // update header map (single latest packet)
        headerMap[header] = pkt;

        auto it2 = endpointHandlers.find(endpoint);
        if (it2 != endpointHandlers.end()) endpointHandler = it2->second;
        // update last endpoint map
        endpointMap[endpoint] = pkt;

        globalHandler = readHandler;
    }

    // Notify one specific waiter (if any) for header and endpoint
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
        auto eit = endpointWaiters.find(endpoint);
        if (eit != endpointWaiters.end() && !eit->second.empty()) {
            std::shared_ptr<Waiter> waiter = eit->second.front();
            {
                std::lock_guard<std::mutex> lk(waiter->mtx);
                waiter->signalled.store(true);
                waiter->cv.notify_one();
            }
        }
    }

    if (headerHandler) headerHandler(pkt);
    if (endpointHandler) endpointHandler(pkt);
    if (globalHandler) globalHandler(pkt);
}

void SongbirdCore::updateEndpointOrder(std::shared_ptr<Packet> pkt) {
    std::lock_guard<std::mutex> lock(dataMutex);
    IStream::Endpoint endpoint = pkt->getEndpoint();
    uint8_t seqNum = pkt->getSequenceNum();

    auto it = endpointOrders.find(endpoint);
    if (it == endpointOrders.end()) {
        endpointOrders[endpoint] = EndpointOrder{seqNum};
        it = endpointOrders.find(endpoint);
    }

    // Keep the most recent sequence seen for repeat detection. Explicit reordering is no longer supported.
    it->second.expectedSeqNum = seqNum;
    it->second.missingTimerActive = true;
    it->second.missingTimerStart = std::chrono::steady_clock::now();
    missingTimerCv.notify_all();
}

bool SongbirdCore::isRepeatPacket(std::shared_ptr<Packet> pkt) {
	// Only check for repeat if guaranteed delivery is enabled
	if (!pkt->isGuaranteed()) return false;

    uint8_t seqNum = pkt->getSequenceNum();
    IStream::Endpoint endpoint = pkt->getEndpoint();

    std::lock_guard<std::mutex> lock(dataMutex);
    auto it = endpointOrders.find(endpoint);
    if (it != endpointOrders.end()) {
        uint8_t expectedSeq = it->second.expectedSeqNum;

        // A packet is a repeat if its sequence number is the same as, or older
        // than, the most recent packet seen from this endpoint. This handles
        // unsigned 8-bit wraparound without reordering packets.
        int8_t diff = (int8_t)seqNum - (int8_t)expectedSeq;
        if (diff <= 0 && diff > -128) {
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
    if (pkt->getHeader() == ACK_HEADER) {
        // This is an ACK packet - remove the acknowledged packet from retransmit queue
        uint8_t ackSeq = pkt->getSequenceNum();
        if (pkt->getPayloadLength() > 0 && pkt->peekByte() == NACK_CODE) {
            onRetransmissionTimeout(ackSeq);
        } else {
            removeAcknowledgedPacket(ackSeq);
        }
        return true; // ACK handled, don't dispatch to handlers
    }

    // Not an ACK packet - check if we need to send an ACK for this packet
    if (pkt->isGuaranteed()) {
        // Send ACK back to sender (even for repeats, in case original ACK was dropped)
        uint8_t seqNum = pkt->getSequenceNum();
        IStream::Endpoint endpoint = pkt->getEndpoint();
        
        // Create ACK packet
        Packet ackPkt(0x00); // ACK header
        ackPkt.setEndpoint(endpoint);
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
        logPacket(LOG_RETRANSMITTED, *info.packet);
        // Resend packet
        sendPacket(*info.packet.get(), info.packet->getSequenceNum(), false);
    }
}



void SongbirdCore::flush() {
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        readBuffer.clear();
        headerMap.clear();
        newPacket = true;
    }
}

std::size_t SongbirdCore::getReadBufferSize() {
    std::lock_guard<std::mutex> lock(dataMutex);
    return readBuffer.size();
}

std::size_t SongbirdCore::getNumIncomingPackets() {
    return 0;
}

void SongbirdCore::appendToReadBuffer(const uint8_t* data, std::size_t length) {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}