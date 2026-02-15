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

        struct Remote {
            IPAddress ip;
            uint16_t port;

            bool operator==(const Remote& o) const {
                return ip == o.ip && port == o.port;
            }
            
            bool operator!=(const Remote& o) const {
                return !(*this == o);
            }
        };

        struct RemoteExpected {
            Remote remote;
            uint8_t seqNum;

            bool operator==(const RemoteExpected& o) const {
                return seqNum == o.seqNum && remote == o.remote;
            }
        };

        struct RemoteOrder {
            uint8_t expectedSeqNum;
            uint32_t missingTimerStartMicros = 0;
            bool missingTimerActive = false;
        };

        // Custom hash functor
        struct RemoteHasher {
            size_t operator()(SongbirdCore::Remote const& r) const noexcept {
                // IPAddress exposes operator[] to access octets
                uint32_t a = (static_cast<uint32_t>(r.ip[0]) << 24) |
                            (static_cast<uint32_t>(r.ip[1]) << 16) |
                            (static_cast<uint32_t>(r.ip[2]) << 8)  |
                            (static_cast<uint32_t>(r.ip[3]));
                // combine ip and port into a size_t
                return std::hash<uint32_t>()(a) ^ (static_cast<size_t>(r.port) << 1);
            }
        };

        struct RemoteExpectedHasher {
            size_t operator()(SongbirdCore::RemoteExpected const& r) const noexcept {
                RemoteHasher rHasher;
                auto h1 = rHasher(r.remote);
                auto h2 = std::hash<uint8_t>()(r.seqNum);
                return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1<<6) + (h1>>2));
            }
        };

        class Packet {
        public:
            // Creates blank packet
            Packet(uint8_t header);
            // Creates packet with a payload
            Packet(uint8_t header, const std::vector<uint8_t>& payload);

            // Converts packet to byte vector for transmission
            std::vector<uint8_t> toBytes(SongbirdCore::ProcessMode mode, SongbirdCore::ReliableMode reliableMode) const;

            // Sets sequence number
            void setSequenceNum(uint8_t seqNum);

            uint8_t getHeader() const;
            uint8_t getSequenceNum() const;
            std::vector<uint8_t> getPayload() const;
            std::size_t getPayloadLength() const;
            std::size_t getRemainingBytes() const;

            // Remote info (for server mode responses)
            void setRemote(const IPAddress& ip, uint16_t port);
            void setRemote(const Remote& remote);
            Remote getRemote() const;
            IPAddress getRemoteIP() const;
            uint16_t getRemotePort() const;

            // Marks the packet as guaranteed
            void setGuaranteed(bool guaranteed = true) { guaranteedFlag = guaranteed; }
            bool isGuaranteed() const { return guaranteedFlag; }

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

            // Remote info (for server mode responses)
            IPAddress remoteIP;
            uint16_t remotePort = 0;
        };

        // Outgoing guaranteed packets by sequence number
        struct OutgoingInfo {
            std::shared_ptr<SongbirdCore::Packet> pkt;
            Remote remote;
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

        // Attach a handler for packets with a particular remote source
        void setRemoteHandler(IPAddress remoteIP, uint16_t remotePort, ReadHandler hander);
        void clearRemoteHandler(IPAddress remoteIP, uint16_t remotePort);

        // Blocking wait for a packet with the given header (returns nullptr on timeout)
        std::shared_ptr<Packet> waitForHeader(uint8_t header, uint32_t timeoutMs);
        // Blocking wait for a packet with the given remote (returns nullptr on timeout)
        std::shared_ptr<Packet> waitForRemote(IPAddress remoteIP, uint16_t remotePort, uint32_t timeoutMs);

        // Attaches stream object
        void attachStream(IStream* stream);
        
        // Update method - call regularly to process timeouts
        void update();

        ////////////////////////////////////////////
        // Specific to packet mode

        // Configure missing-packet timeout (ms)
        void setMissingPacketTimeout(uint32_t ms);
        void onMissingTimeout(const Remote remote);
        void onRetransmitTimeout(uint8_t seqNum);

        // Configure retransmit timeout for guaranteed packets (ms)
        void setRetransmitTimeout(uint32_t ms);
        
        // Configure maximum retransmit attempts (0 = infinite)
        void setMaxRetransmitAttempts(uint8_t attempts);

        // Whether out of order packets are allowed (less latency)
        void setAllowOutofOrder(bool allow);

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
        void parseData(const uint8_t* data, std::size_t length, IPAddress remoteIP, uint16_t remotePort);

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

        std::unordered_map<RemoteExpected, std::shared_ptr<SongbirdCore::Packet>, RemoteExpectedHasher> incomingPackets;

        // Outgoing packet sequence numbers
        uint8_t nextSeqNum;

        // Expected incoming packet sequence numbers by remotes
        std::unordered_map<Remote, RemoteOrder, RemoteHasher> remoteOrders;
        // Missing-packet timeout (milliseconds). If the next expected sequence
        // does not arrive within this window, the core will advance to the
        // next available sequence to avoid blocking forever.
        uint32_t missingPacketTimeoutMs;
        
        // Retransmit timeout for guaranteed packets (milliseconds)
        uint32_t retransmitTimeoutMs;
        
        // Maximum retransmit attempts (0 = infinite retries)
        uint8_t maxRetransmitAttempts;

        uint64_t lastDataTimeMs = 0;

        // Handlers by remotes
        std::unordered_map<Remote, ReadHandler, RemoteHasher> remoteHandlers;

        std::shared_ptr<SongbirdCore::Packet> packetFromData(const uint8_t* data, std::size_t length);
        std::vector<std::shared_ptr<SongbirdCore::Packet>> reorderPackets();
        std::vector<std::shared_ptr<SongbirdCore::Packet>> reorderRemote(const Remote remote, RemoteOrder& remoteOrder);
        
        // Helper to update or create remoteOrder entry
        void updateRemoteOrder(std::shared_ptr<Packet> pkt);
        
        // Helper to check if a packet is a repeat
        bool isRepeatPacket(std::shared_ptr<Packet> pkt);

        ////////////////////////////////////////
        // Specific to stream mode

        // New packet flag (looks for new packet in read buffer)
        bool newPacket = true;

        // Allows out of order packets
        bool allowOutofOrder = true;

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
        // last packet received per remote (for waitForRemote)
        std::unordered_map<Remote, std::shared_ptr<SongbirdCore::Packet>, RemoteHasher> remoteMap;
        // Outgoing guaranteed packet information by sequence number
        std::unordered_map<uint8_t, OutgoingInfo> outgoingGuaranteed;
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