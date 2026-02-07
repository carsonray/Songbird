// Unit tests for SongbirdCore serial communication using a mock IStream.
#include <Arduino.h>
#include <unity.h>

#include "SongbirdCore.h"

#include <memory>
#include <vector>
#include <mutex>
#include <algorithm>

#define MODE SongbirdCore::PACKET
#define RELIABILITY SongbirdCore::UNRELIABLE

class MockStream : public IStream {
public:
    MockStream(std::string name) : protocol(std::make_shared<SongbirdCore>(name, MODE, RELIABILITY)), peer(nullptr), open(true), blocked(false) {
        protocol->attachStream(this);
        protocol->setMissingPacketTimeout(10);
        protocol->setRetransmitTimeout(200); // Short timeout for testing
    }
    ~MockStream() {

    }

    void setPeer(MockStream* p) { peer = p; }

    std::shared_ptr<SongbirdCore> getProtocol() {
        return protocol;
    }

    void write(const uint8_t* buffer, std::size_t length) override {
        // Deliver bytes directly into peer's incoming buffer
        if (!peer) return;
        // Check if peer is blocked from receiving
        if (peer->blocked) return;
        peer->incoming.insert(peer->incoming.end(), buffer, buffer + length);
    }

    bool supportsRemoteWrite() const override { return false; }

    void updateData() {
        // Reads any available data from serial stream
        std::size_t toRead = incoming.size();
        if (toRead == 0) return;
        protocol->parseData(incoming.data(), toRead);
        incoming.clear();
    }

    bool isOpen() const override { return open; }
    void close() override { open = false; }
    
    void setBlocked(bool block) { blocked = block; }
    bool isBlocked() const { return blocked; }

private:
    std::shared_ptr<SongbirdCore> protocol;
    MockStream* peer;
    std::vector<uint8_t> incoming;
    bool open;
    bool blocked;
};

struct LinkedCores {
    std::shared_ptr<MockStream> streamA;
    std::shared_ptr<MockStream> streamB;
    std::shared_ptr<SongbirdCore> coreA;
    std::shared_ptr<SongbirdCore> coreB;
};

static LinkedCores makeLinkedCores() {
    auto s1 = std::make_shared<MockStream>("A");
    auto s2 = std::make_shared<MockStream>("B");
    s1->setPeer(s2.get());
    s2->setPeer(s1.get());

    auto a = s1->getProtocol();
    auto b = s2->getProtocol();
    return {s1, s2, a, b};
}

void setUp() {}
void tearDown() {}

void test_basic_send_receive() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });

    auto pkt = a->createPacket(0x10);
    pkt.writeByte(0x42);
    a->sendPacket(pkt);

    // let B pull bytes and dispatch
    cores.streamB->updateData();
    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "B should have received a packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10, received->getHeader(), "Header mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, received->getPayloadLength(), "Payload length");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x42, received->readByte(), "Payload content");
}

void test_specific_handler() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    uint8_t header = 0x10;

    std::shared_ptr<SongbirdCore::Packet> received;
    b->setHeaderHandler(header, [&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });

    auto pkt = a->createPacket(header);
    pkt.writeByte(0x42);
    a->sendPacket(pkt);

    // let B pull bytes and dispatch
    cores.streamB->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "B should have received a packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10, received->getHeader(), "Header mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, received->getPayloadLength(), "Payload length");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x42, received->readByte(), "Payload content");

    // Additional random packet to test handler specificity
    auto pkt2 = a->createPacket(0x20);
    pkt2.writeByte(0x99);
    a->sendPacket(pkt2);

    // let B pull bytes and dispatch
    cores.streamB->updateData();

    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10, received->getHeader(), "Handler should not have been called for different header");
}

void test_request_response() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    const uint8_t REQ = 0x01;
    const uint8_t RESP = 0x02;

    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        if (pkt->getHeader() == REQ) {
            auto r = b->createPacket(RESP);
            r.writeByte(0x99);
            b->sendPacket(r);
        }
    });

    auto req = a->createPacket(REQ);
    a->sendPacket(req);

    // B processes request and sends response
    cores.streamB->updateData();
    // A receives response
    cores.streamA->updateData();

    auto resp = a->waitForHeader(RESP, 1000);
    TEST_ASSERT_NOT_NULL_MESSAGE(resp.get(), "A should receive a response");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x99, resp->readByte(), "Response payload");

    // Extra: test waitForResponse timeout
    auto resp2 = a->waitForHeader(0xFF, 100);
    TEST_ASSERT_NULL_MESSAGE(resp2.get(), "Should timeout waiting for nonexistent response");
}

void test_reliability_off() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    b->setAllowOutofOrder(true);

    std::vector<uint8_t> headers;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        headers.push_back(pkt->getHeader());
    });

    // Send three packets with out of order sequence numbers
    // Note: Avoid header 0x00 as it's reserved for ACK
    uint8_t seqNums[3] = {1, 3, 2};
    uint8_t sendHeaders[3] = {0x10, 0x13, 0x12};
    for (uint8_t i = 0; i < 3; ++i) {
        auto p = a->createPacket(sendHeaders[i]);
        p.writeByte(seqNums[i]);
        a->sendPacket(p, seqNums[i]);
        // Give B the bytes
        cores.streamB->updateData();
    }

    // Waits for timeout
    vTaskDelay(pdMS_TO_TICKS(50));

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, headers.size(), "Should have received three packets");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(sendHeaders[0], headers[0], "First header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(sendHeaders[1], headers[1], "Second header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(sendHeaders[2], headers[2], "Third header");
}

void test_ordering_reliability() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    b->setAllowOutofOrder(false);

    std::vector<uint8_t> headers;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        headers.push_back(pkt->getHeader());
    });

    // Send three packets with out of order sequence numbers
    // Note: Avoid header 0x00 as it's reserved for ACK
    // Start with seq 1 to avoid needing extra updates for ordering
    uint8_t seqNums[3] = {1, 4, 2};
    uint8_t sendHeaders[3] = {0x11, 0x14, 0x12};
    for (uint8_t i = 0; i < 3; ++i) {
        auto p = a->createPacket(sendHeaders[i]);
        p.writeByte(seqNums[i]);
        a->sendPacket(p, seqNums[i]);
        // Give B the bytes
        cores.streamB->updateData();
    }

    // Waits for timeout
    vTaskDelay(pdMS_TO_TICKS(50));

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, headers.size(), "Should have received three packets");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(sendHeaders[0], headers[0], "First header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(sendHeaders[2], headers[1], "Second header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(sendHeaders[1], headers[2], "Third header");
}

void test_integer_payload() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });

    auto p = a->createPacket(0x30);
    int16_t val = -12345;
    p.writeInt16(val);
    a->sendPacket(p);

    cores.streamB->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "Integer packet not received");
    TEST_ASSERT_EQUAL_INT16_MESSAGE(val, received->readInt16(), "Int16 value mismatch");
}

void test_float_payload() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });

    auto p = a->createPacket(0x31);
    float fv = 3.14159f;
    p.writeFloat(fv);
    a->sendPacket(p);

    cores.streamB->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "Float packet not received");
    float got = received->readFloat();
    // allow small epsilon
    TEST_ASSERT_FLOAT_WITHIN_MESSAGE(0.0001f, fv, got, "Float value mismatch");
}

void test_guaranteed_delivery_with_retransmit() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    int receiveCount = 0;
    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        receiveCount++;
        received = pkt;
    });

    // Block B from receiving (simulates packet loss or unresponsive receiver)
    cores.streamB->setBlocked(true);

    // Send guaranteed packet from A
    auto pkt = a->createPacket(0x50);
    pkt.writeByte(0xAA);
    a->sendPacket(pkt, true); // guaranteeDelivery = true

    // A sends the packet, but B is blocked
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, receiveCount, "B should not receive packet while blocked");

    // Wait for first retransmit timeout
    vTaskDelay(pdMS_TO_TICKS(60));
    
    // A should have retransmitted, but B is still blocked
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, receiveCount, "B should still not receive while blocked");

    // Unblock B
    cores.streamB->setBlocked(false);

    // Wait for another retransmit timeout (need to wait full timeout period)
    vTaskDelay(pdMS_TO_TICKS(250));
    
    // B should now receive the retransmitted packet and send ACK
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, receiveCount, "B should receive packet after unblocking");
    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "B should have received a packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x50, received->getHeader(), "Header mismatch");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xAA, received->readByte(), "Payload content");

    // A should receive the ACK
    cores.streamA->updateData();

    // Wait to ensure no more retransmits occur after ACK
    vTaskDelay(pdMS_TO_TICKS(80));
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, receiveCount, "Should not receive duplicate after ACK");
}

void test_repeat_blocking() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    int receiveCount = 0;
    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        receiveCount++;
        received = pkt;
    });

    // Send first packet to establish sequence number
    auto pkt1 = a->createPacket(0x60);
    pkt1.writeByte(0xBB);
    a->sendPacket(pkt1);
    
    // B receives the first packet
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, receiveCount, "B should receive first packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xBB, received->readByte(), "First packet payload");

    // Send second packet with higher sequence number
    auto pkt2 = a->createPacket(0x61);
    pkt2.writeByte(0xCC);
    a->sendPacket(pkt2, true);
    
    // B receives the second packet
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, receiveCount, "B should receive second packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xCC, received->readByte(), "Second packet payload");
    
    // A receives ACK from B
    cores.streamA->updateData();

    // Now manually send a packet with a lower sequence number (repeat)
    auto pkt3 = a->createPacket(0x62);
    pkt3.writeByte(0xDD);
    // Use sequence number 255 which is lower than the current sequence (with wraparound)
    a->sendPacket(pkt3, 255, true);
    
    // B should receive the packet but filter it as a repeat
    cores.streamB->updateData();
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, receiveCount, "B should block repeat packet");
}

// STREAM mode tests with COBS encoding
class StreamMockStream : public IStream {
public:
    StreamMockStream(std::string name) : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM, SongbirdCore::UNRELIABLE)), peer(nullptr), open(true) {
        protocol->attachStream(this);
        protocol->setMissingPacketTimeout(10);
    }
    
    void setPeer(StreamMockStream* p) { peer = p; }
    std::shared_ptr<SongbirdCore> getProtocol() { return protocol; }
    
    void write(const uint8_t* buffer, std::size_t length) override {
        if (!peer) return;
        peer->incoming.insert(peer->incoming.end(), buffer, buffer + length);
    }
    
    bool supportsRemoteWrite() const override { return false; }
    
    void updateData() {
        std::size_t toRead = incoming.size();
        if (toRead == 0) return;
        protocol->parseData(incoming.data(), toRead);
        incoming.clear();
    }
    
    bool isOpen() const override { return open; }
    void close() override { open = false; }
    
private:
    std::shared_ptr<SongbirdCore> protocol;
    StreamMockStream* peer;
    std::vector<uint8_t> incoming;
    bool open;
};

void test_stream_mode_basic() {
    auto s1 = std::make_shared<StreamMockStream>("A");
    auto s2 = std::make_shared<StreamMockStream>("B");
    s1->setPeer(s2.get());
    s2->setPeer(s1.get());
    
    auto a = s1->getProtocol();
    auto b = s2->getProtocol();
    
    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });
    
    auto pkt = a->createPacket(0x70);
    pkt.writeByte(0xAB);
    pkt.writeByte(0xCD);
    a->sendPacket(pkt);
    
    s2->updateData();
    
    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "B should receive STREAM mode packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x70, received->getHeader(), "Header mismatch in STREAM");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(2, received->getPayloadLength(), "Payload length in STREAM");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xAB, received->readByte(), "First byte");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0xCD, received->readByte(), "Second byte");
}

void test_stream_mode_multiple_packets() {
    auto s1 = std::make_shared<StreamMockStream>("A");
    auto s2 = std::make_shared<StreamMockStream>("B");
    s1->setPeer(s2.get());
    s2->setPeer(s1.get());
    
    auto a = s1->getProtocol();
    auto b = s2->getProtocol();
    
    std::vector<std::shared_ptr<SongbirdCore::Packet>> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received.push_back(pkt);
    });
    
    // Send multiple packets
    for (uint8_t i = 0; i < 3; i++) {
        auto pkt = a->createPacket(0x71 + i);
        pkt.writeByte(0x10 + i);
        a->sendPacket(pkt);
    }
    
    s2->updateData();
    
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, received.size(), "Should receive 3 packets");
    for (uint8_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x71 + i, received[i]->getHeader(), "Header mismatch");
        TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10 + i, received[i]->readByte(), "Payload mismatch");
    }
}

void test_string_serialization() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });

    auto pkt = a->createPacket(0x80);
    pkt.writeString("Hello, World!");
    pkt.writeString("");  // Empty string
    pkt.writeString("Test");
    a->sendPacket(pkt);

    cores.streamB->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "String packet not received");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("Hello, World!", received->readString().c_str(), "First string mismatch");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", received->readString().c_str(), "Empty string mismatch");
    TEST_ASSERT_EQUAL_STRING_MESSAGE("Test", received->readString().c_str(), "Third string mismatch");
}

void test_protobuf_serialization() {
    auto cores = makeLinkedCores();
    auto a = cores.coreA;
    auto b = cores.coreB;

    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });

    // Simulate protobuf data (just raw bytes for testing)
    std::vector<uint8_t> protoData1 = {0x08, 0x96, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74};
    std::vector<uint8_t> protoData2 = {0x01, 0x02, 0x03};

    auto pkt = a->createPacket(0x81);
    pkt.writeProtobuf(protoData1);
    pkt.writeProtobuf(protoData2);
    a->sendPacket(pkt);

    cores.streamB->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "Protobuf packet not received");
    
    auto result1 = received->readProtobuf();
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(protoData1.size(), result1.size(), "First protobuf size mismatch");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(protoData1.data(), result1.data(), protoData1.size(), "First protobuf data mismatch");
    
    auto result2 = received->readProtobuf();
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(protoData2.size(), result2.size(), "Second protobuf size mismatch");
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(protoData2.data(), result2.data(), protoData2.size(), "Second protobuf data mismatch");
}

void test_stream_mode_zero_bytes_in_payload() {
    auto s1 = std::make_shared<StreamMockStream>("A");
    auto s2 = std::make_shared<StreamMockStream>("B");
    s1->setPeer(s2.get());
    s2->setPeer(s1.get());
    
    auto a = s1->getProtocol();
    auto b = s2->getProtocol();
    
    std::shared_ptr<SongbirdCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
        received = pkt;
    });
    
    // Test COBS encoding handles zero bytes in payload correctly
    auto pkt = a->createPacket(0x75);
    pkt.writeByte(0x00);  // Zero byte
    pkt.writeByte(0x01);
    pkt.writeByte(0x00);  // Another zero byte
    pkt.writeByte(0x02);
    a->sendPacket(pkt);
    
    s2->updateData();
    
    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "Should handle zero bytes in payload");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x75, received->getHeader(), "Header mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(4, received->getPayloadLength(), "Payload length");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x00, received->readByte(), "First zero byte");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x01, received->readByte(), "Non-zero byte");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x00, received->readByte(), "Second zero byte");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x02, received->readByte(), "Last byte");
}

void setup() {
    UNITY_BEGIN();
    RUN_TEST(test_basic_send_receive);
    RUN_TEST(test_specific_handler);
    RUN_TEST(test_request_response);
    RUN_TEST(test_reliability_off);
    RUN_TEST(test_ordering_reliability);
    RUN_TEST(test_integer_payload);
    RUN_TEST(test_float_payload);
    RUN_TEST(test_guaranteed_delivery_with_retransmit);
    RUN_TEST(test_repeat_blocking);
    RUN_TEST(test_string_serialization);
    RUN_TEST(test_protobuf_serialization);
    RUN_TEST(test_stream_mode_basic);
    RUN_TEST(test_stream_mode_multiple_packets);
    RUN_TEST(test_stream_mode_zero_bytes_in_payload);
    UNITY_END();
}

void loop() {}
