// ...existing code...
#ifndef RUDP_CORE_H
#define RUDP_CORE_H

#include <vector>
#include <mutex>
#include <chrono>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <thread>
#include <queue>
#include <functional>
#include <atomic>
#include <condition_variable>

#include "IStream.h"

class RUDPCore {
    public:
        class Packet {
        public:
            // Creates blank packet
            Packet();
            // Creates packet with header and sequence number
            Packet(uint8_t sequenceNum, uint8_t header);
            // Creates packet with a payload
            Packet(uint8_t sequenceNum, uint8_t header, const std::vector<uint8_t>& payload);

            // Converts packet to byte vector for transmission
            std::vector<uint8_t> toBytes() const;

            int64_t getSequenceNum() const;
            uint8_t getHeader() const;
            std::size_t getPayloadLength() const;

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
            uint8_t sequenceNum;
            uint8_t header;
            std::size_t payloadLength;
            std::vector<uint8_t> payload;
            // read cursor into payload
            mutable std::size_t readPos = 0;
        };

        using ReadHandler = std::function<void(std::shared_ptr<RUDPCore::Packet>)>;

        RUDPCore(std::string name);
        ~RUDPCore();

        // Attaches a stream to the protocol
        void attachStream(std::shared_ptr<IStream> stream);

        //Sets general read handler (invoked for all incoming packets)
        void setReadHandler(ReadHandler handler);

        // Attach a response handler for packets with a particular header
        void setSpecificHandler(uint8_t header, ReadHandler handler);
        void clearSpecificHandler(uint8_t header);

        // Blocking wait for a response packet with the given header (returns nullptr on timeout)
        std::shared_ptr<Packet> waitForHeader(uint8_t header, uint32_t timeoutMs);

        // Gets stream object
        std::shared_ptr<IStream> getStream();

        // Creates a blank packet with a specified header
        Packet createPacket(uint8_t header);

        // Sends a packet
        void sendPacket(const Packet& packet);

        // Holds a packet in the write buffer
        void holdPacket(const Packet& packet);

        // Sends all data in write buffer
        void sendAll();

        // Fetches data from stream and processes packets
        void updateData();

        // Configure missing-packet timeout (ms)
        void setMissingPacketTimeout(uint32_t ms);

        // Reliability control: when disabled, incoming packets are dispatched
        // immediately as parsed (no ordering or timeout applied).
        void setReliabilityEnabled(bool enabled);
        bool isReliabilityEnabled() const;

        // Flushes all buffers
        void flush();

        std::size_t getReadBufferSize();
        std::size_t getWriteBufferSize();

        // Buffer management
        void appendToReadBuffer(const uint8_t* data, std::size_t length);
        void appendToWriteBuffer(const uint8_t* data, std::size_t length);

    private:
        std::string name;
        std::shared_ptr<IStream> stream;
        std::vector<uint8_t> readBuffer;
        std::vector<uint8_t> writeBuffer;
        std::unordered_map<uint8_t, std::shared_ptr<RUDPCore::Packet>> incomingPackets;

        // Outgoing packet sequence numbers
        std::atomic<uint8_t> nextSeqNum;

        // Expected incoming packet sequence number
        uint8_t expectedSeqNum;
        // Missing-packet timeout (milliseconds). If the next expected sequence
        // does not arrive within this window, the core will advance to the
        // next available sequence to avoid blocking forever.
        uint32_t missingPacketTimeoutMs;

        // Timestamp when we started waiting for the next expected sequence.
        std::chrono::steady_clock::time_point missingSince;
        bool missingTimerActive;
        // When true the core enforces ordering and timeouts; when false packets
        // are dispatched immediately as they are parsed.
        bool reliabilityEnabled;

        // Current incoming packet temporary fields (used by characterizePacket)
        uint8_t currSeqNum = 0;
        uint8_t currHeader = 0;
        std::size_t currPayloadLen = 0;

        // New packet flag (looks for new packet in read buffer)
        bool newPacket = true;

        // Characterizes incoming packet (inspects readBuffer and returns true if a full packet is available)
        bool characterizePacket();

        // Triggers handlers based on packet
        void callHandlers(std::shared_ptr<Packet> pkt);

        mutable std::mutex dataMutex;
        mutable std::mutex waitMutex;

        //Read handler (global)
        ReadHandler readHandler;

        // Response handlers keyed by header
        std::unordered_map<uint8_t, ReadHandler> specificHandlers;
        std::condition_variable_any waitCv;
        // last response packet received per header (for waitForResponse)
        std::unordered_map<uint8_t, std::shared_ptr<RUDPCore::Packet>> lastHeaderMap;
};

template <typename T>
T RUDPCore::Packet::readData() {
    T data;
    uint8_t buffer[sizeof(data)];
    readBytes(buffer, sizeof(data));

    std::memcpy(&data, buffer, sizeof(data));

    return data;
}

#endif // RUDP_CORE_H