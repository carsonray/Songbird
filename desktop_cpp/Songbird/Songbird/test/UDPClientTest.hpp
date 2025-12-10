// UDP client test (counterpart to the Arduino test runner)
// Mirrors UARTMasterTest but uses SongbirdUDP instead of SongbirdUART.
// Usage: UDPClientTest (the test will send to localhost:12345 by default)

#ifdef BUILD_UDP_TEST

#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>
#include <cmath>
#include <cstdio>

#include <boost/asio.hpp>

#include "../src/SongbirdCore.h"
#include "../src/SongbirdUDP.h"

#define UDP_REMOTE_ADDR "192.168.0.114"
#define UDP_REMOTE_PORT 8080

#define UDP_LOCAL_PORT 8080

// UDP node object
SongbirdUDP udp("UDP Node");
// UDP server protocol object
std::shared_ptr<SongbirdCore> core;

// Waits for ping from remote
static void waitForPing()
{
    std::cout << "Waiting for ping from remote";
    std::shared_ptr<SongbirdCore::Packet> response = nullptr;
    while (!response) {
        auto pkt = core->createPacket(0xFF); // Ping packet
        core->sendPacket(pkt);
        response = core->waitForHeader(0xFF, 1000); // Wait for ping
        std::cout << ".";
    }
    std::cout << "\nPing received from remote.\n";
}

static bool run_basic_send_receive() {
    bool ok = false;
    auto pkt = core->createPacket(0x10);
    pkt.writeByte(0x42);
    core->sendPacket(pkt);

    core->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
            ok = true;
        }
    });

    auto start = std::chrono::steady_clock::now();
    while (!ok && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return ok;
}

static bool run_specific_handler() {
    bool ok = false;

    auto pkt = core->createPacket(0x10);
    pkt.writeByte(0x42);
    core->sendPacket(pkt);

    core->setHeaderHandler(0x10, [&](std::shared_ptr<SongbirdCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
            ok = true;
        }
    });

    auto start = std::chrono::steady_clock::now();
    while (!ok && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (!ok) return false;

    //Additional random packet to test handler specificity
    ok = false;

    auto pkt2 = core->createPacket(0x11);
    pkt2.writeByte(0x42);
    core->sendPacket(pkt2);

    start = std::chrono::steady_clock::now();
    while (!ok && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return !ok;
}

static bool run_request_response() {
    // Sends request packet
    auto req = core->createPacket(0x01);
    core->sendPacket(req);

    // Waits for response packet
    auto response = core->waitForHeader(0x01, 2000);
    return (response && response->getHeader() == 0x01 && response->getPayloadLength() == 1 && response->readByte() == 0x99);
}

static bool run_integer_payload() {
    auto req = core->createPacket(0x30);
    req.writeInt16(-12345);
    core->sendPacket(req);
    auto resp = core->waitForHeader(0x30, 2000);
    if (!resp) return false;
    if (resp->getHeader() != 0x30 || resp->getPayloadLength() != 2) return false;
    int16_t v = resp->readInt16();
    if (v != -12345) return false;
    return true;
}

static bool run_float_payload() {
    auto req = core->createPacket(0x31);
    req.writeFloat(3.14159f);
    core->sendPacket(req);
    auto resp = core->waitForHeader(0x31, 2000);
    if (!resp) return false;
    if (resp->getHeader() != 0x31 || resp->getPayloadLength() != 4) return false;
    float v = resp->readFloat();
    if (fabs(v - 3.14159f) >= 0.0002f) return false;
    return true;
}

int main() {
    // Gets data protocol
    core = udp.getProtocol();

    udp.begin();
    // Begins connection
    if (!udp.listen(UDP_LOCAL_PORT)) {
        return 1;
    }

    // Configure remote endpoint (defaults to localhost:12345)
    udp.setRemote(boost::asio::ip::make_address(UDP_REMOTE_ADDR), UDP_REMOTE_PORT);

    waitForPing();

    bool pass = true;

    std::cout << "\nRunning basic send/receive...\n";
    if (run_basic_send_receive()) std::cout << "\nbasic_send_receive: PASS\n"; else { std::cout << "\nbasic_send_receive: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\nRunning specific handler test...\n";
    if (run_specific_handler()) std::cout << "\nspecific_handler: PASS\n"; else { std::cout << "\nspecific_handler: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\nRunning request/response test \n";
    if (run_request_response()) std::cout << "\nrequest_response: PASS\n"; else { std::cout << "\nrequest_response: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\nRunning integer payload test...\n";
    if (run_integer_payload()) std::cout << "\ninteger_payload: PASS\n"; else { std::cout << "\ninteger_payload: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\nRunning float payload test...\n";
    if (run_float_payload()) std::cout << "\nfloat_payload: PASS\n"; else { std::cout << "\nfloat_payload: FAIL\n"; pass = false; }

    std::cout << "\nOverall: " << (pass ? "PASS" : "FAIL") << "\n";

    auto embeddedResult = core->waitForHeader(0x00, 2000);
    std::cout << "\nEmbedded test results: " << (embeddedResult && embeddedResult->readByte() ? "PASS" : "FAIL") << "\n";

    return 0;
}

#endif // BUILD_UDP_TEST
