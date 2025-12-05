// ...existing code...
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

        class Packet {
        public:
            // Creates blank packet
            Packet(uint8_t header);
            // Creates packet with a payload
            Packet(uint8_t header, const std::vector<uint8_t>& payload);

            // Converts packet to byte vector for transmission
            std::vector<uint8_t> toBytes(SongbirdCore::ProcessMode mode) const;

            // Sets sequence number
            void setSequenceNum(uint8_t seqNum);

            uint8_t getHeader() const;
            int64_t getSequenceNum() const;
            std::size_t getPayloadLength() const;
            std::size_t getRemainingBytes() const;

            // Remote info (for server mode responses)
            void setRemoteInfo(const std::string& ip, uint16_t port) {
                remoteIP = ip;
                remotePort = port;
            }
            std::string getRemoteIP() const;
            uint16_t getRemotePort() const;

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

            // Remote info (for server mode responses)
            std::string remoteIP;
            uint16_t remotePort = 0;
        };

        using ReadHandler = std::function<void(std::shared_ptr<SongbirdCore::Packet>)>;

        SongbirdCore(std::string name, ProcessMode mode = PACKET);
        ~SongbirdCore();

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

        ////////////////////////////////////////////
        // Specific to packet mode

        // Configure missing-packet timeout (ms)
        void setMissingPacketTimeout(uint32_t ms);

        ////////////////////////////////////////////
        // Specific to stream mode
        // Holds a packet in the write buffer
        void holdPacket(const Packet& packet);

        // Sends all data in write buffer
        void sendAll();

        // Flushes all buffers
        void flush();

        // Gets buffer sizes
        std::size_t getReadBufferSize();
        std::size_t getWriteBufferSize();

        //////////////////////////////////////////////
        // Both modes

        // Creates a new packet
        Packet createPacket(uint8_t header);

        // Sends a packet
        void sendPacket(Packet& packet);

        // Parses data from stream
        void parseData(const uint8_t* data, std::size_t length);
        void parseData(const uint8_t* data, std::size_t length, std::string remoteIP, uint16_t remotePort);

    private:
        std::string name;
        std::shared_ptr<IStream> stream;
        std::vector<uint8_t> readBuffer;
        std::vector<uint8_t> writeBuffer;

        //Process mode
        ProcessMode processMode;

        ///////////////////////////////////////
        // Specific to packet mode

        std::unordered_map<uint8_t, std::shared_ptr<SongbirdCore::Packet>> incomingPackets;

        // Outgoing packet sequence numbers
        std::atomic<uint8_t> nextSeqNum;

        // Expected incoming packet sequence number
        uint8_t expectedSeqNum;
        // Missing-packet timeout (milliseconds). If the next expected sequence
        // does not arrive within this window, the core will advance to the
        // next available sequence to avoid blocking forever.
        uint32_t missingPacketTimeoutMs;

        // Timestamp (millis) when we started waiting for the next expected sequence.
        unsigned long missingSinceMs;
        bool missingTimerActive;

        std::shared_ptr<SongbirdCore::Packet> packetFromData(const uint8_t* data, std::size_t length);
        std::vector<std::shared_ptr<SongbirdCore::Packet>> dispatchPackets();

        ////////////////////////////////////////
        // Specific to stream mode

        // New packet flag (looks for new packet in read buffer)
        bool newPacket = true;

        // Returns the next packet in readBuffer if there is one
        std::shared_ptr<Packet> packetFromStream();

        // Buffer management
        void appendToReadBuffer(const uint8_t* data, std::size_t length);
        void appendToWriteBuffer(const uint8_t* data, std::size_t length);

        ////////////////////////////////////////
        // Both modes

        // Triggers handlers based on packet
        void callHandlers(std::shared_ptr<Packet> pkt);

        // Short critical sections use a spinlock (portMUX). Longer operations
        // can use semaphores if needed. Using spinlocks avoids heap usage and
        // is suitable for short protected regions.
        mutable portMUX_TYPE dataSpinlock;

        //Read handler (global)
        ReadHandler readHandler;

        // Response handlers keyed by header
        std::unordered_map<uint8_t, ReadHandler> specificHandlers;
        // last packet received per header (for waitForHeader)
        std::unordered_map<uint8_t, std::shared_ptr<SongbirdCore::Packet>> lastHeaderMap;
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