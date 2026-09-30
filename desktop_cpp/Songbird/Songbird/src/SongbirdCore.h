#ifndef SONGBIRD_CORE_H
#define SONGBIRD_CORE_H

#include <vector>
#include <mutex>
#include <chrono>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <boost/asio.hpp>
#include <memory>
#include <thread>
#include <queue>
#include <functional>
#include <atomic>
#include <condition_variable>

#include "IStream.h"

class SongbirdCore {
    public:
        enum ProcessMode {
            STREAM,
            PACKET
        };

        enum ReliableMode {
            UNRELIABLE,
            RELIABLE
		};

        struct EndpointOrder {
            uint8_t expectedSeqNum = 0;
            bool missingTimerActive = false;
            std::chrono::steady_clock::time_point missingTimerStart = std::chrono::steady_clock::time_point::min();
        };

        // Custom hash functor
        struct EndpointHasher {
            size_t operator()(IStream::Endpoint const& endpoint) const noexcept {
                // combine ip and port into a size_t
                return std::hash<std::string>()(endpoint.ip.to_string()) ^ (static_cast<size_t>(endpoint.port) << 1);
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
            
            // Guaranteed delivery flag
            void setGuaranteed(bool guaranteed = true);
            bool isGuaranteed() const;

            uint8_t getHeader() const;
            uint8_t getSequenceNum() const;
            std::vector<uint8_t> getPayload() const;
            std::size_t getPayloadLength() const;
            std::size_t getRemainingBytes() const;

            // Endpoint info (for server mode responses)
            void setEndpoint(const boost::asio::ip::address &ip, uint16_t port);
            void setEndpoint(const IStream::Endpoint& endpoint);
            IStream::Endpoint getEndpoint() const;

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
            bool guaranteedFlag;
            std::size_t payloadLength;
            std::vector<uint8_t> payload;
            // read cursor into payload
            mutable std::size_t readPos = 0;

            // Endpoint info (for server mode responses)
            IStream::Endpoint endpoint;
        };

        // Guaranteed packet tracking structure (defined after Packet class)
        struct OutgoingInfo {
            std::shared_ptr<Packet> packet;
            IStream::Endpoint endpoint;
            std::chrono::steady_clock::time_point sendTime;
            uint32_t retransmitCount = 0;
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

        ////////////////////////////////////////////
        // Specific to packet mode

        // Configure missing-packet timeout (ms)
        void setMissingPacketTimeout(uint32_t ms);
        void setRetransmissionTimeout(uint32_t ms);
        void setMaxRetransmitAttempts(uint32_t attempts);
		void onRetransmissionTimeout(uint8_t seqNum);

        std::size_t getNumIncomingPackets();

        ////////////////////////////////////////////
        // Specific to stream mode

        // Flushes all buffers
        void flush();

        // Gets buffer sizes
        std::size_t getReadBufferSize();
        
        //////////////////////////////////////////////
        // Both modes

        // Creates a new packet (header 0x00 reserved for ACKs)
        Packet createPacket(uint8_t header);

        // Sends a packet with optional guaranteed delivery
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
        std::atomic<uint8_t> nextSeqNum;

        // Last sequence number seen per endpoint, used for repeat detection.
        std::unordered_map<IStream::Endpoint, EndpointOrder, EndpointHasher> endpointOrders;
        
        // Guaranteed delivery tracking: packets awaiting ACK
        std::unordered_map<uint8_t, OutgoingInfo> outgoingGuaranteed;

        // Missing-packet timeout (milliseconds). If the next expected sequence
        // does not arrive within this window, the core will advance to the
        // next available sequence to avoid blocking forever.
        uint32_t missingPacketTimeoutMs;
        uint32_t retransmissionTimeoutMs;
        uint32_t maxRetransmitAttempts;

        uint64_t lastDataTimeMs = 0;

        // Handlers by endpoints
        std::unordered_map<IStream::Endpoint, ReadHandler, EndpointHasher> endpointHandlers;

        std::shared_ptr<SongbirdCore::Packet> packetFromData(const uint8_t* data, std::size_t length);
        
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

        // ACK handling
        void removeAcknowledgedPacket(uint8_t seqNum);
        bool checkForAck(std::shared_ptr<Packet> packet);

        // Helper to update or create endpoint order entry
        void updateEndpointOrder(std::shared_ptr<Packet>);

        // Helper to check if a packet is a repeat
        bool isRepeatPacket(std::shared_ptr<Packet> pkt);

        std::mutex dataMutex;
        std::mutex waitMutex;
        std::condition_variable waitCv;

        //Read handler (global)
        ReadHandler readHandler;

        // Response handlers keyed by header
        std::unordered_map<uint8_t, ReadHandler> headerHandlers;
        // last packet received per header (for waitForHeader)
        std::unordered_map<uint8_t, std::shared_ptr<SongbirdCore::Packet>> headerMap;
        // last packet received per endpoint (for waitForEndpoint)
        std::unordered_map<IStream::Endpoint, std::shared_ptr<SongbirdCore::Packet>, EndpointHasher> endpointMap;

        // Internal waiter object used to avoid missed notifications
        struct Waiter {
            std::mutex mtx;
            std::condition_variable cv;
            std::atomic<bool> signalled{false};
        };

        // Waiter registries (per-header and per-endpoint) to support multiple concurrent waiters
        std::unordered_map<uint8_t, std::vector<std::shared_ptr<Waiter>>> headerWaiters;
        std::unordered_map<IStream::Endpoint, std::vector<std::shared_ptr<Waiter>>, EndpointHasher> endpointWaiters;

        // Timer thread and synchronization for desktop missing-packet timeout handling
        std::thread missingTimerThread;
        std::mutex missingTimerMutex;
        std::condition_variable missingTimerCv;
        std::atomic<bool> missingTimerThreadStop{false};
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