#ifndef SONGBIRD_CORE_H
#define SONGBIRD_CORE_H

#include <vector>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <queue>
#include <functional>
#include <atomic>
#include <memory>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include <Arduino.h>

#include "IStream.h"

// Global RAII helper for spinlock critical sections
struct SpinLockGuard {
    portMUX_TYPE* mux;
    explicit SpinLockGuard(portMUX_TYPE& m) : mux(&m) { portENTER_CRITICAL(mux); }
    ~SpinLockGuard() { portEXIT_CRITICAL(mux); }
};

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
        };

        struct RemoteExpected {
            Remote remote;
            uint8_t seqNum;

            bool operator==(const RemoteExpected& o) const {
                return seqNum == o.seqNum && remote == o.remote;
            }
        };

        struct TimeoutID {
            SongbirdCore* owner;
            Remote remote;
        };
        
        struct RemoteOrder {
            uint8_t expectedSeqNum;
            TimeoutID timeoutID;
            TimerHandle_t missingTimer = nullptr;
            bool missingTimerActive = false;
            bool needsTimerStart = false;
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

        // Timer helper for retransmission
        struct RetransmitID { SongbirdCore* owner; uint8_t seq; };

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

            // Reading functions (consume payload bytes)
            uint8_t readByte();
            uint8_t peekByte() const;
            void readBytes(uint8_t* buffer, std::size_t len);
            float readFloat();
            int16_t readInt16();

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
            TimerHandle_t timer = nullptr;
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
        std::atomic<uint8_t> nextSeqNum;

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

        TimerHandle_t startRetransmitTimer(uint8_t seqNum);

        std::shared_ptr<SongbirdCore::Packet> packetFromData(const uint8_t* data, std::size_t length);
        std::vector<std::shared_ptr<SongbirdCore::Packet>> reorderPackets();
        std::vector<std::shared_ptr<SongbirdCore::Packet>> reorderRemote(const Remote remote, RemoteOrder& remoteOrder, std::vector<TimerHandle_t>& timersToStop);
        TimerHandle_t startMissingTimer(RemoteOrder& remoteOrder);
        
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
        std::shared_ptr<Packet> packetFromStream();

        // Buffer management
        void appendToReadBuffer(const uint8_t* data, std::size_t length);
        ////////////////////////////////////////
        // Both modes

        // Triggers handlers based on packet
        void callHandlers(std::shared_ptr<Packet> pkt);

        // Remove acknowledged packet from outgoing map and stop timer
        void removeAcknowledgedPacket(uint8_t seqNum);
        
        // Check if packet is an ACK and handle it, or send ACK if packet is guaranteed
        // Returns true if packet is an ACK (and should not be dispatched to handlers)
        bool checkForAck(std::shared_ptr<Packet> pkt);

        // Short critical sections use a spinlock (portMUX). Longer operations
        // can use semaphores if needed. Using spinlocks avoids heap usage and
        // is suitable for short protected regions.
        mutable portMUX_TYPE dataSpinlock;

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

void missingTimerCallback(TimerHandle_t xTimer);

#endif // SONGBIRD_CORE_H