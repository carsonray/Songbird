            String endpointText = String(packet.getEndpoint().toString().c_str());
    Serial.print(endpoint.toString().c_str());
    Serial.print(entry.first.toString().c_str());
    if (endpoint == IStream::Endpoint{}) {
#include <Arduino.h>
#include "SongbirdCore.h"

#include <algorithm>
#include <cassert>

/// Packet implementation
SongbirdCore::Packet::Packet(uint8_t header)
    : header(header), sequenceNum(0), payloadLength(0), payload(), readPos(0), guaranteedFlag(false) {}

SongbirdCore::Packet::Packet(uint8_t header, const std::vector<uint8_t>& payload)
    : header(header), sequenceNum(0), payloadLength(payload.size()), payload(payload), readPos(0), guaranteedFlag(false) {}

SongbirdCore::Packet::Packet(uint8_t header, const std::vector<uint8_t>& payload, bool checksumOk)
    : header(header), sequenceNum(0), payloadLength(payload.size()), payload(payload), readPos(0), guaranteedFlag(false), checksumOk(checksumOk) {}

std::vector<uint8_t> SongbirdCore::Packet::toBytes(SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode) const {
    std::vector<uint8_t> out;
    
    if (reliableMode == SongbirdCore::RELIABLE) {
        // RELIABLE mode: no seq/guaranteed bytes
        // STREAM: [header][payload] (COBS encoded)
        // PACKET: [header][payload]
        out.reserve(1 + payloadLength);
        out.push_back(header);
    } else {
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

// SongbirdCore implementation

SongbirdCore::SongbirdCore(std::string name, SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode)
    : self(this), name(std::move(name)), processMode(mode), reliableMode(reliableMode), nextSeqNum(0), missingPacketTimeoutMs(50), retransmitTimeoutMs(50), maxRetransmitAttempts(5)
{
    // Initialize spinlock based on platform
    #if defined(ESP32)
        // Create FreeRTOS mutex semaphore
        dataSpinlock = xSemaphoreCreateMutex();
    #elif defined(PICO_SDK)
        critical_section_init(&dataSpinlock);
    #else
        dataSpinlock = 0;
    #endif
}

SongbirdCore::~SongbirdCore() {
    flush();
    
    // Cleanup spinlock based on platform
    #if defined(ESP32)
        if (dataSpinlock) vSemaphoreDelete(dataSpinlock);
    #elif defined(PICO_SDK)
        critical_section_deinit(&dataSpinlock);
    #endif
}

void SongbirdCore::attachStream(IStream* stream) {
    this->stream = stream;
}

void SongbirdCore::setLogging(const Logging& value) {
    SpinLockGuard guard(dataSpinlock);
    logging = value;
    headerLogTracks.clear();
    endpointLogTracks.clear();
    logRateWindowStartMs = millis();
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

void SongbirdCore::logPacket(LogEvent event, const Packet& packet, const char* reason) {
    bool shouldLog = false;
    bool rateEnabled = false;
    {
        SpinLockGuard guard(dataSpinlock);
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

        shouldLog = (logging.events & event) != 0;
        rateEnabled = (logging.events & LOG_RATE) != 0;
        if (shouldLog) {
            String endpointText = String(packet.getEndpoint().toString().c_str());
            Serial.print("["); Serial.print(name.c_str()); Serial.print("] ");
            Serial.print(logEventName(event));
            Serial.print(" header="); Serial.print(packet.getHeader());
            Serial.print(" seq="); Serial.print(packet.getSequenceNum());
            Serial.print(" guaranteed="); Serial.print(packet.isGuaranteed() ? 1 : 0);
            Serial.print(" payload="); Serial.print(packet.getPayloadLength());
            Serial.print(" endpoint="); Serial.print(endpointText);
            if (reason) { Serial.print(" reason="); Serial.print(reason); }
            Serial.println();
        }
    }
    if (shouldLog || rateEnabled) logRatesIfDue();
}

void SongbirdCore::logTimeout(const IStream::Endpoint& endpoint) {
    SpinLockGuard guard(dataSpinlock);
    if (!(logging.events & LOG_DROPPED) ||
        (logging.filterEndpoint && !(endpoint == logging.endpoint)) || logging.filterHeader) return;
    Serial.print("["); Serial.print(name.c_str());
    Serial.print("] DROPPED header=? seq=? guaranteed=? payload=? endpoint=");
    Serial.print(endpoint.toString().c_str());
    Serial.println(" reason=timeout");
}

void SongbirdCore::logRatesIfDue() {
    SpinLockGuard guard(dataSpinlock);
    if (!(logging.events & LOG_RATE) || logging.rateIntervalMs == 0) return;
    uint32_t elapsed = millis() - logRateWindowStartMs;
    if (elapsed < logging.rateIntervalMs) return;

    for (const auto& entry : headerLogTracks) {
        Serial.print("["); Serial.print(name.c_str()); Serial.print("] RATE header=");
        Serial.print(entry.first); Serial.print(" sent="); Serial.print(entry.second.sent);
        Serial.print(" received="); Serial.print(entry.second.received);
        Serial.print(" pps="); Serial.println((entry.second.sent + entry.second.received) * 1000UL / elapsed);
    }
    for (const auto& entry : endpointLogTracks) {
        Serial.print("["); Serial.print(name.c_str()); Serial.print("] RATE endpoint=");
        Serial.print(entry.first.toString().c_str());
        Serial.print(" sent="); Serial.print(entry.second.sent);
        Serial.print(" received="); Serial.print(entry.second.received);
        Serial.print(" pps="); Serial.println((entry.second.sent + entry.second.received) * 1000UL / elapsed);
    }
    headerLogTracks.clear();
    endpointLogTracks.clear();
    logRateWindowStartMs = millis();
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

void SongbirdCore::setEndpointHandler(const IStream::Endpoint& endpoint, ReadHandler handler) {
    SpinLockGuard guard(dataSpinlock);
    endpointHandlers[endpoint] = std::move(handler);
}

void SongbirdCore::clearEndpointHandler(const IStream::Endpoint& endpoint) {
    SpinLockGuard guard(dataSpinlock);
    endpointHandlers.erase(endpoint);
    endpointMap.erase(endpoint);
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
        // Poll for new data
        if (stream) stream->updateData();
        
        {
            SpinLockGuard guard(dataSpinlock);
            auto it = headerMap.find(header);
            if (it != headerMap.end()) {
                auto pkt = it->second;
                headerMap.erase(it);
                return pkt;
            }
        }
        delay(1);
    }
    return nullptr;
}

std::shared_ptr<SongbirdCore::Packet> SongbirdCore::waitForEndpoint(const IStream::Endpoint& endpoint, uint32_t timeoutMs) {
    // First check if a packet is already available
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = endpointMap.find(endpoint);
        if (it != endpointMap.end()) {
            auto pkt = it->second;
            endpointMap.erase(it);
            return pkt;
        }
    }

    unsigned long start = millis();
    while ((millis() - start) < timeoutMs) {
        // Poll for new data
        if (stream) stream->updateData();
        
        {
            SpinLockGuard guard(dataSpinlock);
            auto it = endpointMap.find(endpoint);
            if (it != endpointMap.end()) {
                auto pkt = it->second;
                endpointMap.erase(it);
                return pkt;
            }
        }
        delay(1);
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

void SongbirdCore::sendPacket(Packet& packet, bool guaranteeDelivery) {
    uint8_t seqNum = nextSeqNum++;
    sendPacket(packet, seqNum, guaranteeDelivery);
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
    IStream::Endpoint endpoint = packet.getEndpoint();
    if (endpoint == IStream::Endpoint{}) {
        endpoint = stream->getEndpoint();
        packet.setEndpoint(endpoint);
    }
    stream->write(bytes.data(), bytes.size(), endpoint);
    logPacket(LOG_SENT, packet);

    // Track guaranteed packets and record send time (UNRELIABLE mode only)
    if (guaranteeDelivery && reliableMode == UNRELIABLE) {
        OutgoingInfo info{std::make_shared<Packet>(packet), packet.getEndpoint(), micros(), 0};
        {
            SpinLockGuard guard(dataSpinlock);
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
        // This ensures ACKs are sent immediately even if packet gets buffered as out-of-order
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
    } else if (processMode == STREAM) {
        // Adds data to readBuffer
        appendToReadBuffer(data, length);
        // Record byte arrival time so fragmented frames can accumulate.
        if (length > 0) {
            lastDataTimeMs = millis();
        }
        // Process COBS-encoded packets in readBuffer
        while (true) {
            std::shared_ptr<Packet> pkt = packetFromStreamCOBS();
            if (!pkt) {
                if (millis() - lastDataTimeMs > missingPacketTimeoutMs) {
                    // Timeout: clear read buffer to avoid stale data
                    logTimeout(endpoint);
                    flush();
                }
                break;
            }
            lastDataTimeMs = millis();
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

            // Updates remote order for UNRELIABLE mode (for all packets for sequencing)
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
    } else {
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
    SpinLockGuard guard(dataSpinlock);
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
        uint8_t checksum = 0;
        for (size_t i = 0; i + 1 < decoded.size(); ++i) checksum ^= decoded[i];
        bool checksumValid = decoded.size() >= 4 && checksum == decoded.back();
        std::vector<uint8_t> payload;
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
        SpinLockGuard guard(dataSpinlock);

        auto it = headerHandlers.find(header);
        if (it != headerHandlers.end()) headerHandler = it->second;
        // update header map
        headerMap[header] = pkt;

        auto it2 = endpointHandlers.find(endpoint);
        if (it2 != endpointHandlers.end()) endpointHandler = it2->second;
        // update last endpoint map
        endpointMap[endpoint] = pkt;
        
        globalHandler = readHandler;
    }

    if (headerHandler) headerHandler(pkt);
    if (endpointHandler) endpointHandler(pkt);
    if (globalHandler) globalHandler(pkt);
}

void SongbirdCore::updateEndpointOrder(std::shared_ptr<Packet> pkt) {
    IStream::Endpoint endpoint = pkt->getEndpoint();
    uint8_t seqNum = pkt->getSequenceNum();
    uint32_t now = millis();

    SpinLockGuard guard(dataSpinlock);
    for (auto it = endpointOrders.begin(); it != endpointOrders.end();) {
        if (it->second.missingTimerActive &&
            static_cast<uint32_t>(now - it->second.missingTimerStartMs) >= missingPacketTimeoutMs) {
            endpointMap.erase(it->first);
            it = endpointOrders.erase(it);
        } else {
            ++it;
        }
    }

    EndpointOrder& order = endpointOrders[endpoint];
    order.expectedSeqNum = seqNum;
    order.missingTimerActive = true;
    order.missingTimerStartMs = now;
}

bool SongbirdCore::isRepeatPacket(std::shared_ptr<Packet> pkt) {
    if (!pkt->isGuaranteed()) return false;

    uint8_t seqNum = pkt->getSequenceNum();
    IStream::Endpoint endpoint = pkt->getEndpoint();

    SpinLockGuard guard(dataSpinlock);
    auto it = endpointOrders.find(endpoint);
    if (it != endpointOrders.end()) {
        uint8_t expectedSeq = it->second.expectedSeqNum;

        // A packet is a repeat if its sequence is the same as, or older than,
        // the most recent packet seen from this endpoint; wraparound is handled
        // by comparing signed 8-bit deltas.
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
    
    // Check if this is an ACK or NACK packet.
    if (pkt->getHeader() == ACK_HEADER) {
        uint8_t ackSeq = pkt->getSequenceNum();
        if (pkt->getPayloadLength() > 0 && pkt->peekByte() == NACK_CODE) {
            onRetransmitTimeout(ackSeq);
        } else {
            removeAcknowledgedPacket(ackSeq);
        }
        return true; // ACK handled, don't dispatch to handlers
    }
    
    // Not an ACK packet - check if we need to send an ACK for this packet
    if (pkt->isGuaranteed()) {
        // Send ACK back to sender
        uint8_t seqNum = pkt->getSequenceNum();
        IStream::Endpoint endpoint = pkt->getEndpoint();
        
        // Create ACK packet
        Packet ackPkt(0x00); // ACK header
        ackPkt.setEndpoint(endpoint);
        // Send ACK packet (even for repeats, in case the ACK was dropped)
        sendPacket(ackPkt, seqNum, false);
    }
    
    return isRepeatPacket(pkt); // Not an ACK, should be dispatched to handlers
}

void SongbirdCore::removeAcknowledgedPacket(uint8_t seqNum) {
    SpinLockGuard guard(dataSpinlock);
    auto it = outgoingGuaranteed.find(seqNum);
    if (it != outgoingGuaranteed.end()) {
        outgoingGuaranteed.erase(it);
    }
}

void SongbirdCore::onRetransmitTimeout(uint8_t seqNum) {
    bool needsResend = false;
    OutgoingInfo info;
    
    {
        SpinLockGuard guard(dataSpinlock);
        auto it = outgoingGuaranteed.find(seqNum);
        if (it != outgoingGuaranteed.end()) {
            info = it->second;
            
            // Check if we've exceeded max retransmit attempts (0 = infinite)
            if (maxRetransmitAttempts > 0 && info.retransmitCount >= maxRetransmitAttempts) {
                // Max attempts reached, clean up and stop retransmitting
                outgoingGuaranteed.erase(it);
            } else {
                // Increment retransmit counter and update send time
                it->second.retransmitCount++;
                it->second.sendTimeMicros = micros();
                needsResend = true;
            }
        }
    }
    
    if (needsResend) {
        logPacket(LOG_RETRANSMITTED, *info.pkt);
        // Resend packet
        sendPacket(*info.pkt.get(), info.pkt->getSequenceNum(), false);
    }
}

void SongbirdCore::flush() {
    {
        SpinLockGuard guard(dataSpinlock);
        readBuffer.clear();
        headerMap.clear();
        newPacket = true;
    }
}

std::size_t SongbirdCore::getReadBufferSize() {
    SpinLockGuard guard(dataSpinlock);
    return readBuffer.size();
}

std::size_t SongbirdCore::getNumIncomingPackets() {
    return 0;
}

void SongbirdCore::appendToReadBuffer(const uint8_t* data, std::size_t length) {
    SpinLockGuard guard(dataSpinlock);
    if (length == 0) return;
    readBuffer.insert(readBuffer.end(), data, data + length);
}

void SongbirdCore::update() {
    uint32_t currentMicros = micros();
    std::vector<uint8_t> expiredRetransmitSeqs;
    
    {
        SpinLockGuard guard(dataSpinlock);
        
        // Check for retransmit timeouts
        for (auto& it : outgoingGuaranteed) {
            uint8_t seqNum = it.first;
            OutgoingInfo& info = it.second;
            
            uint32_t elapsedMicros = currentMicros - info.sendTimeMicros;
            uint32_t timeoutMicros = retransmitTimeoutMs * 1000;
            
            if (elapsedMicros >= timeoutMicros) {
                expiredRetransmitSeqs.push_back(seqNum);
            }
        }
    }
    
    // Handle expired retransmit timeouts outside the lock
    for (uint8_t seqNum : expiredRetransmitSeqs) {
        onRetransmitTimeout(seqNum);
    }
}