// Unit tests for RUDPCore serial communication using a mock IStream.
#include <Arduino.h>
#include <unity.h>

#include "RUDPCore.h"

#include <memory>
#include <vector>
#include <mutex>
#include <algorithm>

class MockStream : public IStream {
public:
    MockStream() : peer(nullptr), open(true) {}

    void setPeer(MockStream* p) { peer = p; }

    void enableReverse(bool rev) {
        reverse = rev;
    }

    void write(const uint8_t* buffer, std::size_t length) override {
        // Deliver bytes directly into peer's incoming buffer
        if (!peer) return;
        if (!reverse) {
            peer->incoming.insert(peer->incoming.end(), buffer, buffer + length);
        } else {
            // write to front of peer incoming buffer
            peer->incoming.insert(peer->incoming.begin(), buffer, buffer + length);
        }
    }

    std::size_t read(uint8_t* buffer, std::size_t length) override {
        // single-threaded; no locking
        std::size_t toRead = std::min(length, incoming.size());
        if (toRead) {
            std::memcpy(buffer, incoming.data(), toRead);
            incoming.erase(incoming.begin(), incoming.begin() + toRead);
        }
        return toRead;
    }

    uint8_t available() override {
        return static_cast<uint8_t>(std::min<size_t>(incoming.size(), 255));
    }

    bool isOpen() const override { return open; }
    void close() override { open = false; }

private:
    MockStream* peer;
    std::vector<uint8_t> incoming;
    bool open;
    bool reverse = false;
};

static std::pair<std::shared_ptr<RUDPCore>, std::shared_ptr<RUDPCore>> makeLinkedCores() {
    auto s1 = std::make_shared<MockStream>();
    auto s2 = std::make_shared<MockStream>();
    s1->setPeer(s2.get());
    s2->setPeer(s1.get());

    auto a = std::make_shared<RUDPCore>("A");
    auto b = std::make_shared<RUDPCore>("B");
    a->attachStream(s1);
    b->attachStream(s2);
    return {a, b};
}

void setUp() {}
void tearDown() {}

void test_basic_send_receive() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    std::shared_ptr<RUDPCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
        received = pkt;
    });

    auto pkt = a->createPacket(0x10);
    pkt.writeByte(0x42);
    a->sendPacket(pkt);

    // let B pull bytes and dispatch
    b->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "B should have received a packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10, received->getHeader(), "Header mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, received->getPayloadLength(), "Payload length");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x42, received->readByte(), "Payload content");
}

void test_specific_handler() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    uint8_t header = 0x10;

    std::shared_ptr<RUDPCore::Packet> received;
    b->setResponseHandler(header, [&](std::shared_ptr<RUDPCore::Packet> pkt){
        received = pkt;
    });

    auto pkt = a->createPacket(header);
    pkt.writeByte(0x42);
    a->sendPacket(pkt);

    // let B pull bytes and dispatch
    b->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "B should have received a packet");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10, received->getHeader(), "Header mismatch");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(1, received->getPayloadLength(), "Payload length");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x42, received->readByte(), "Payload content");

    // Additional random packet to test handler specificity
    auto pkt2 = a->createPacket(0x20);
    pkt2.writeByte(0x99);
    a->sendPacket(pkt2);

    // let B pull bytes and dispatch
    b->updateData();

    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x10, received->getHeader(), "Handler should not have been called for different header");
}

void test_request_response() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    const uint8_t REQ = 0x01;
    const uint8_t RESP = 0x02;

    b->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
        if (pkt->getHeader() == REQ) {
            auto r = b->createPacket(RESP);
            r.writeByte(0x99);
            b->sendPacket(r);
        }
    });

    auto req = a->createPacket(REQ);
    a->sendPacket(req);

    // B processes request and sends response
    b->updateData();
    // A receives response
    a->updateData();

    auto resp = a->waitForResponse(RESP, 1000);
    TEST_ASSERT_NOT_NULL_MESSAGE(resp.get(), "A should receive a response");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0x99, resp->readByte(), "Response payload");

    // Extra: test waitForResponse timeout
    auto resp2 = a->waitForResponse(0xFF, 100);
    TEST_ASSERT_NULL_MESSAGE(resp2.get(), "Should timeout waiting for nonexistent response");
}

void test_reliability_off() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    b->setReliabilityEnabled(false);

    std::vector<uint8_t> headers;
    b->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
        headers.push_back(pkt->getHeader());
    });

    // Send three packets in sequence
    for (uint8_t h = 1; h <= 3; ++h) {
        ((MockStream*)a->getStream().get())->enableReverse(h % 2 == 0);  // reverse every other packet to simulate out-of-order arrival
        auto p = a->createPacket(h);
        p.writeByte(h + 10);
        a->sendPacket(p);
    }

    // Give B the bytes
    b->updateData();
    // Call update a few times to allow processing
    for (int i = 0; i < 5; ++i) b->updateData();

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, headers.size(), "Should have received three packets");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(2, headers[0], "First header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, headers[1], "Second header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(3, headers[2], "Third header");
}

void test_ordering_reliability() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    std::vector<uint8_t> headers;
    b->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
        headers.push_back(pkt->getHeader());
    });

    // Send three packets in sequence
    for (uint8_t h = 1; h <= 3; ++h) {
        ((MockStream*)a->getStream().get())->enableReverse(h % 2 == 0);  // reverse every other packet to simulate out-of-order arrival
        auto p = a->createPacket(h);
        p.writeByte(h + 10);
        a->sendPacket(p);
    }

    // Give B the bytes
    b->updateData();
    // Call update a few times to allow ordering logic to run
    for (int i = 0; i < 5; ++i) b->updateData();

    TEST_ASSERT_EQUAL_UINT32_MESSAGE(3, headers.size(), "Should have received three packets");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(1, headers[0], "First header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(2, headers[1], "Second header");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(3, headers[2], "Third header");
}

void test_integer_payload() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    std::shared_ptr<RUDPCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
        received = pkt;
    });

    auto p = a->createPacket(0x30);
    int16_t val = -12345;
    p.writeInt16(val);
    a->sendPacket(p);

    b->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "Integer packet received");
    TEST_ASSERT_EQUAL_INT16_MESSAGE(val, received->readInt16(), "Int16 value mismatch");
}

void test_float_payload() {
    auto cores = makeLinkedCores();
    auto a = cores.first;
    auto b = cores.second;

    std::shared_ptr<RUDPCore::Packet> received;
    b->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
        received = pkt;
    });

    auto p = a->createPacket(0x31);
    float fv = 3.14159f;
    p.writeFloat(fv);
    a->sendPacket(p);

    b->updateData();

    TEST_ASSERT_NOT_NULL_MESSAGE(received.get(), "Float packet received");
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
