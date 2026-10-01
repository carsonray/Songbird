#ifndef SONGBIRD_CORE_H
#define SONGBIRD_CORE_H

#include <vector>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <queue>
#include <functional>
#include <memory>

#include <Arduino.h>

#include "IStream.h"

// Conditional spinlock implementation based on platform
#if defined(ESP32)
    // ESP32 FreeRTOS mutex semaphore
    #include "freertos/FreeRTOS.h"
    #include "freertos/semphr.h"
    
    struct SpinLockGuard {
        SemaphoreHandle_t mutex;
        explicit SpinLockGuard(SemaphoreHandle_t m) : mutex(m) { 
            if (mutex) xSemaphoreTake(mutex, portMAX_DELAY); 
        }
        ~SpinLockGuard() { 
            if (mutex) xSemaphoreGive(mutex); 
        }
    };
    
    typedef SemaphoreHandle_t SpinLock_t;
    
#elif defined(PICO_SDK)
    // Raspberry Pi Pico SDK spinlock
    #include "pico/critical_section.h"
    
    struct SpinLockGuard {
        critical_section_t* cs;
        explicit SpinLockGuard(critical_section_t& c) : cs(&c) { critical_section_enter_blocking(cs); }
        ~SpinLockGuard() { critical_section_exit(cs); }
    };
    
    typedef critical_section_t SpinLock_t;
    #define SPINLOCK_INITIALIZER {}
    
#else
    // Default: dummy spinlock (no-op for single-threaded environments)
    struct SpinLockGuard {
        explicit SpinLockGuard(int&) {}
        ~SpinLockGuard() {}
    };
    
    typedef int SpinLock_t;
    #define SPINLOCK_INITIALIZER 0
    
#endif

class SongbirdCore {
    public:
        enum ProcessMode {
            STREAM,
            PACKET
        };
        
        enum ReliableMode {
            UNRELIABLE,  // Uses sequence numbers and guaranteed delivery
            RELIABLE     // Does not use sequence numbers or guaranteed delivery
        };

        static constexpr uint8_t ACK_HEADER = 0x00;
        static constexpr uint8_t NACK_CODE = 0x01;

        enum LogEvent : uint8_t {
            LOG_DROPPED = 1 << 0,
            LOG_RETRANSMITTED = 1 << 1,
            LOG_SENT = 1 << 2,
            LOG_RECEIVED = 1 << 3,
            LOG_RATE = 1 << 4
        };

        struct Logging {
            uint8_t events = 0;
            bool filterEndpoint = false;
            IStream::Endpoint endpoint;
            bool filterHeader = false;
            uint8_t header = 0;
            uint32_t rateIntervalMs = 1000;
        };

        struct EndpointOrder {
            uint8_t expectedSeqNum = 0;
            bool missingTimerActive = false;
            uint32_t missingTimerStartMs = 0;
        };

        // Custom hash functor
        struct EndpointHasher {
            size_t operator()(IStream::Endpoint const& endpoint) const noexcept {
                return std::hash<std::string>()(endpoint.toString());
            }
        };

        class Packet {
        public:
            // Creates blank packet
            Packet(uint8_t header);
            // Creates packet with a payload
            Packet(uint8_t header, const std::vector<uint8_t>& payload);
            Packet(uint8_t header, const std::vector<uint8_t>& payload, bool checksumValid);

            // Converts packet to byte vector for transmission
            std::vector<uint8_t> toBytes(SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode) const;

            // Sets sequence number
            void setSequenceNum(uint8_t seqNum);

            uint8_t getHeader() const;
            uint8_t getSequenceNum() const;
            std::vector<uint8_t> getPayload() const;
            std::size_t getPayloadLength() const;
            std::size_t getRemainingBytes() const;

            // Endpoint info (for server mode responses)
            void setEndpoint(const IStream::Endpoint& endpoint);
            IStream::Endpoint getEndpoint() const;

            // Marks the packet as guaranteed
            void setGuaranteed(bool guaranteed = true) { guaranteedFlag = guaranteed; }
            bool isGuaranteed() const { return guaranteedFlag; }
            bool isChecksumValid() const { return checksumOk; }
            bool checksumOk = true;

            // Writing functions
            void writeBytes(const uint8_t* buffer, std::size_t length);
            void writeByte(uint8_t value);
            void writeFloat(float value);
            // Writes a 16 bit integer
            void writeInt16(int16_t data);
            // Writes a string with length prefix (uint16_t length + string bytes)
            void writeString(const std::string& str);
            // Writes a length-prefixed byte array (for protobuf messages)
            void writeProtobuf(const uint8_t* buffer, std::size_t length);
            void writeProtobuf(const std::vector<uint8_t>& data);

            // Reading functions (consume payload bytes)
            uint8_t readByte();
            uint8_t peekByte() const;
            void readBytes(uint8_t* buffer, std::size_t len);
            float readFloat();
            int16_t readInt16();
            // Reads a length-prefixed string
            std::string readString();
            // Reads a length-prefixed byte array (for protobuf messages)
            std::vector<uint8_t> readProtobuf();

            template <typename T>
            T readData();

        private:
            uint8_t header;
            uint8_t sequenceNum;
            std::size_t payloadLength;
            std::vector<uint8_t> payload;
            // read cursor into payload
            mutable std::size_t readPos = 0;

            // Guaranteed delivery flag
            bool guaranteedFlag = false;

            // Endpoint info (for server mode responses)
            IStream::Endpoint endpoint;
        };

        // Outgoing guaranteed packets by sequence number
        struct OutgoingInfo {
            std::shared_ptr<SongbirdCore::Packet> pkt;
            IStream::Endpoint endpoint;
            uint32_t sendTimeMicros = 0;
            uint8_t retransmitCount = 0;
        };

        using ReadHandler = std::function<void(std::shared_ptr<SongbirdCore::Packet>)>;

        SongbirdCore(std::string name, ProcessMode mode = PACKET, ReliableMode reliableMode = UNRELIABLE);
        ~SongbirdCore();

        //Sets general read handler (invoked for all incoming packets)
        void setReadHandler(ReadHandler handler);

        // Attach a handler for packets with a particular header
        void setHeaderHandler(uint8_t header, ReadHandler handler);
        void clearHeaderHandler(uint8_t header);

        // Attach a handler for packets with a particular endpoint source
        void setEndpointHandler(const IStream::Endpoint& endpoint, ReadHandler hander);
        void clearEndpointHandler(const IStream::Endpoint& endpoint);

        // Blocking wait for a packet with the given header (returns nullptr on timeout)
        std::shared_ptr<Packet> waitForHeader(uint8_t header, uint32_t timeoutMs);
        // Blocking wait for a packet with the given endpoint (returns nullptr on timeout)
        std::shared_ptr<Packet> waitForEndpoint(const IStream::Endpoint& endpoint, uint32_t timeoutMs);

        // Attaches stream object
        void attachStream(IStream* stream);
        void setLogging(const Logging& logging);
        
        // Update method - call regularly to process timeouts
        void update();

        ////////////////////////////////////////////
        // Specific to packet mode

        // Configure missing-packet timeout (ms)
        void setMissingPacketTimeout(uint32_t ms);
        void onRetransmitTimeout(uint8_t seqNum);

        // Configure retransmit timeout for guaranteed packets (ms)
        void setRetransmitTimeout(uint32_t ms);
        
        // Configure maximum retransmit attempts (0 = infinite)
        void setMaxRetransmitAttempts(uint8_t attempts);

        std::size_t getNumIncomingPackets();

        ////////////////////////////////////////////
        // Both modes

        // Flushes all buffers
        void flush();

        // Gets buffer sizes
        std::size_t getReadBufferSize();

        // Creates a new packet
        Packet createPacket(uint8_t header);

        // Sends a packet
        void sendPacket(Packet& packet, bool guaranteeDelivery = false);
        void sendPacket(Packet& packet, uint8_t seqNum, bool guaranteeDelivery = false);

        // Parses data from stream
        void parseData(const uint8_t* data, std::size_t length);
        void parseData(const uint8_t* data, std::size_t length, const IStream::Endpoint& endpoint);

    private:
        SongbirdCore* self;
        std::string name;
        IStream* stream;
        std::vector<uint8_t> readBuffer;

        //Process mode
        ProcessMode processMode;
        
        //Reliable mode
        ReliableMode reliableMode;

        ///////////////////////////////////////
        // Specific to packet mode

        // Outgoing packet sequence numbers
        uint8_t nextSeqNum;

        // Most recent sequence number seen per endpoint for duplicate detection.
        std::unordered_map<IStream::Endpoint, EndpointOrder, EndpointHasher> endpointOrders;
        // Missing-packet timeout (milliseconds). If the next expected sequence
        // does not arrive within this window, the core will advance to the
        // next available sequence to avoid blocking forever.
        uint32_t missingPacketTimeoutMs;
        
        // Retransmit timeout for guaranteed packets (milliseconds)
        uint32_t retransmitTimeoutMs;
        
        // Maximum retransmit attempts (0 = infinite retries)
        uint8_t maxRetransmitAttempts;

        uint64_t lastDataTimeMs = 0;

        // Handlers by endpoints
        std::unordered_map<IStream::Endpoint, ReadHandler, EndpointHasher> endpointHandlers;

        std::shared_ptr<SongbirdCore::Packet> packetFromData(const uint8_t* data, std::size_t length);
        
        // Helper to update or create endpoint order entry
        void updateEndpointOrder(std::shared_ptr<Packet> pkt);
        
        // Helper to check if a packet is a repeat
        bool isRepeatPacket(std::shared_ptr<Packet> pkt);

        ////////////////////////////////////////
        // Specific to stream mode

        // New packet flag (looks for new packet in read buffer)
        bool newPacket = true;

        // Returns the next packet in readBuffer if there is one
        std::shared_ptr<Packet> packetFromStreamCOBS();

        // Buffer management
        void appendToReadBuffer(const uint8_t* data, std::size_t length);
        
        // COBS encoding/decoding utilities
        static std::vector<uint8_t> cobsEncode(const uint8_t* data, std::size_t length);
        static std::vector<uint8_t> cobsDecode(const uint8_t* data, std::size_t length);
        ////////////////////////////////////////
        // Both modes

        // Triggers handlers based on packet
        void callHandlers(std::shared_ptr<Packet> pkt);

        struct LogTrack {
            uint32_t sent = 0;
            uint32_t received = 0;
        };

        bool loggingMatches(const IStream::Endpoint& endpoint, uint8_t header) const;
        void logPacket(LogEvent event, const Packet& packet, const char* reason = nullptr);
        void logTimeout(const IStream::Endpoint& endpoint);
        void logRatesIfDue();
        static const char* logEventName(LogEvent event);

        // Remove acknowledged packet from outgoing map and stop timer
        void removeAcknowledgedPacket(uint8_t seqNum);
        
        // Check if packet is an ACK and handle it, or send ACK if packet is guaranteed
        // Returns true if packet is an ACK (and should not be dispatched to handlers)
        bool checkForAck(std::shared_ptr<Packet> pkt);

        // Spinlock for protecting data structures from concurrent access
        mutable SpinLock_t dataSpinlock;

        //Read handler (global)
        ReadHandler readHandler;

        // Response handlers keyed by header
        std::unordered_map<uint8_t, ReadHandler> headerHandlers;
        // last packet received per header (for waitForHeader)
        std::unordered_map<uint8_t, std::shared_ptr<SongbirdCore::Packet>> headerMap;
        // last packet received per endpoint (for waitForEndpoint)
        std::unordered_map<IStream::Endpoint, std::shared_ptr<SongbirdCore::Packet>, EndpointHasher> endpointMap;
        // Outgoing guaranteed packet information by sequence number
        std::unordered_map<uint8_t, OutgoingInfo> outgoingGuaranteed;

        Logging logging;
        std::unordered_map<uint8_t, LogTrack> headerLogTracks;
        std::unordered_map<IStream::Endpoint, LogTrack, EndpointHasher> endpointLogTracks;
        uint32_t logRateWindowStartMs = 0;
};

template <typename T>
T SongbirdCore::Packet::readData() {
    T data;
    uint8_t buffer[sizeof(data)];
    readBytes(buffer, sizeof(data));

    std::memcpy(&data, buffer, sizeof(data));

    return data;
}

#endif // SONGBIRD_CORE_H