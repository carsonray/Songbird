//Main template (counterpart to the Arduino test runner)
//
// Simple desktop test runner that mirrors the Arduino integration tests.
// Usage: RUDPInterface.exe <device> [baud]
// Example (Windows): RUDPInterface.exe COM3 115200
// Example (POSIX)  : RUDPInterface.exe /dev/ttyUSB0 115200

#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>
#include <cmath>

#include <boost/asio.hpp>

#include "RUDPCore.h"
#include "RUDPSerialNode.h"
#include "SerialStream.h"

#define SERIAL_PORT "\\\\.\\COM5"
#define SERIAL_BAUD_RATE 115200

//Serial node object
RUDPSerialNode interface("Middleware Interface");
//Serial server protocol object
std::shared_ptr<RUDPCore> interfaceData;

// Waits for ping from microcontroller
static void waitForPing()
{
    // Waits to flush initial serial data
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    interfaceData->flush();
    std::cout << "Waiting for ping from microcontroller";
    std::shared_ptr<RUDPCore::Packet> response = nullptr;
    while (!response) {
        auto pkt = interfaceData->createPacket(0xFF); // Ping packet
        interfaceData->sendPacket(pkt);
        response = interfaceData->waitForHeader(0xFF, 1000); // Wait for ping
        std::cout << ".";
    }
    std::cout << "\nPing received from microcontroller.\n";
}

static bool run_basic_send_receive() {
    bool ok = false;
    auto pkt = interfaceData->createPacket(0x10);
    pkt.writeByte(0x42);
    interfaceData->sendPacket(pkt);

    interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt) {
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

    auto pkt = interfaceData->createPacket(0x10);
    pkt.writeByte(0x42);
    interfaceData->sendPacket(pkt);

    interfaceData->setResponseHandler(0x10, [&](std::shared_ptr<RUDPCore::Packet> pkt) {
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

    auto pkt2 = interfaceData->createPacket(0x11);
    pkt2.writeByte(0x42);
    interfaceData->sendPacket(pkt2);

    start = std::chrono::steady_clock::now();
    while (!ok && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return !ok;
}

static bool run_request_response() {
    bool gotResponse = false;

    interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x01 && pkt->getPayloadLength() >= 1 && pkt->readByte() == 0x99) gotResponse = true;
        });

    auto req = interfaceData->createPacket(0x01);
    interfaceData->sendPacket(req);

    interfaceData->waitForHeader(0x01, 2000);
    return gotResponse;
}

static bool run_integer_payload() {
    bool ok = false;

    auto p = interfaceData->createPacket(0x30);
    p.writeInt16(static_cast<int16_t>(-12345));
    interfaceData->sendPacket(p);

    interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x30 && pkt->getPayloadLength() == 2) {
            int16_t v = pkt->readInt16();
            if (v == -12345) ok = true;
        }
        });

    auto start = std::chrono::steady_clock::now();
    while (!ok && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return ok;
}

static bool run_float_payload() {
    bool ok = false;

    auto p = interfaceData->createPacket(0x31);
    p.writeFloat(3.14159f);
    interfaceData->sendPacket(p);

    interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x31 && pkt->getPayloadLength() == 4) {
            float v = pkt->readFloat();
            if (std::fabs(v - 3.14159f) < 0.0002f) ok = true;
        }
        });

    auto start = std::chrono::steady_clock::now();
    while (!ok && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count() < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return ok;
}

int main() {
    // Gets data protocol
    interfaceData = interface.getProtocol();

    // Begins connection
    interface.begin(SERIAL_PORT, SERIAL_BAUD_RATE);

    waitForPing();

    bool pass = true;

    std::cout << "\nRunning basic send/receive...\n";
    if (run_basic_send_receive()) std::cout << "\nbasic_send_receive: PASS\n"; else { std::cout << "\nbasic_send_receive: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\nRunning specific handler test...\n";
    if (run_specific_handler()) std::cout << "\nspecific_handler: PASS\n"; else { std::cout << "\nspecific_handler: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::cout << "\nRunning request/response test (local echo)...\n";
    if (run_request_response()) std::cout << "\nrequest_response: PASS\n"; else { std::cout << "\nrequest_response: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    std::cout << "\nRunning integer payload test...\n";
    if (run_integer_payload()) std::cout << "\ninteger_payload: PASS\n"; else { std::cout << "\ninteger_payload: FAIL\n"; pass = false; }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    std::cout << "\nRunning float payload test...\n";
    if (run_float_payload()) std::cout << "\nfloat_payload: PASS\n"; else { std::cout << "\nfloat_payload: FAIL\n"; pass = false; }

    std::cout << "\nOverall: " << (pass ? "PASS" : "FAIL") << "\n";

    auto embeddedResult = interfaceData->waitForHeader(0x00, 2000);
	std::cout << "\nEmbedded test results: " << (embeddedResult && embeddedResult->readByte() ? "PASS" : "FAIL") << "\n";

    return 0;
}