// Unit tests for SongbirdCore serial communication using a mock IStream.
#include <Arduino.h>
#include <unity.h>

#include "SongbirdCore.h"

#include <memory>
#include <vector>
#include <mutex>
#include <algorithm>

#define MODE SongbirdCore::PACKET

class MockStream : public IStream {
public:
    MockStream(std::string name) : protocol(std::make_shared<SongbirdCore>(name, MODE)), peer(nullptr), open(true) {
        protocol->attachStream(this);
        protocol->setMissingPacketTimeout(10);
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
        peer->incoming.insert(peer->incoming.end(), buffer, buffer + length);
    }

    void updateData() {
        // Reads any available data from serial stream
        std::size_t toRead = incoming.size();
        if (toRead == 0) return;
        protocol->parseData(incoming.data(), toRead);
        incoming.clear();
    }

    bool isOpen() const override { return open; }
    void close() override { open = false; }

private:
    std::shared_ptr<SongbirdCore> protocol;
    MockStream* peer;
    std::vector<uint8_t> incoming;
    bool open;
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
    uint8_t seqNums[3] = {1, 0, 2};
    for (uint8_t i = 0; i < 3; ++i) {
        auto p = a->createPacket(seqNums[i]);
        p.writeByte(seqNums[i]);
        a->sendPacket(p, seqNums[i]);
        // Give B the bytes
        cores.streamB->updateData();
    }

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, headers.size(), "Should have received three packets");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, headers[0], "First header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, headers[1], "Second header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(2, headers[2], "Third header");
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
    // Has to start with zero otherwise needs extra updates
    uint8_t seqNums[3] = {0, 2, 1};
    for (uint8_t i = 0; i < 3; ++i) {
        auto p = a->createPacket(seqNums[i]);
        p.writeByte(seqNums[i]);
        a->sendPacket(p, seqNums[i]);
        // Give B the bytes
        cores.streamB->updateData();
    }
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, headers.size(), "Should have received three packets");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, headers[0], "First header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, headers[1], "Second header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(2, headers[2], "Third header");
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

void setup() {
    UNITY_BEGIN();
    RUN_TEST(test_basic_send_receive);
    RUN_TEST(test_specific_handler);
    RUN_TEST(test_request_response);
    RUN_TEST(test_reliability_off);
    RUN_TEST(test_ordering_reliability);
    RUN_TEST(test_integer_payload);
    RUN_TEST(test_float_payload);
    UNITY_END();
}

void loop() {}
