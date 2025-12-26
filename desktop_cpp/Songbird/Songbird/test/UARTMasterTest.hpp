//Main template (counterpart to the Arduino test runner)
//
// Simple desktop test runner that mirrors the Arduino integration tests.
// Usage: RUDPInterface.exe <device> [baud]
// Example (Windows): RUDPInterface.exe COM3 115200
// Example (POSIX)  : RUDPInterface.exe /dev/ttyUSB0 115200

#ifdef BUILD_UART_TEST

#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>
#include <cmath>

#include <boost/asio.hpp>

#include "../src/SongbirdCore.h"
#include "../src/SongbirdUART.h"

#define SERIAL_PORT "\\\\.\\COM6"
#define SERIAL_BAUD_RATE 115200

//Serial node object
SongbirdUART uart("UART Node");
//Serial server protocol object
std::shared_ptr<SongbirdCore> core;

// Waits for ping from microcontroller
static void waitForPing()
{
    // Waits to flush initial serial data
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    core->flush();
    std::cout << "Waiting for ping from microcontroller";
    std::shared_ptr<SongbirdCore::Packet> response = nullptr;
    while (!response) {
        auto pkt = core->createPacket(0xFF); // Ping packet
        core->sendPacket(pkt);
        response = core->waitForHeader(0xFF, 1000); // Wait for ping
        std::cout << ".";
    }
    std::cout << "\nPing received from microcontroller.\n";
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
    core = uart.getProtocol();

    // Begins connection
    uart.begin(SERIAL_PORT, SERIAL_BAUD_RATE);

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

    auto embeddedResult = core->waitForHeader(0xFE, 2000);
    bool embeddedPass = false;
    uint8_t firstFailedTest = 0;

    if (embeddedResult && embeddedResult->getPayloadLength() >= 1) {
        embeddedPass = embeddedResult->readByte();
        if (embeddedResult->getPayloadLength() >= 2) {
            firstFailedTest = embeddedResult->readByte();
        } else {
			std::cout << "No first failed test index received.\n";
		}
    }
    else {
		std::cout << "No embedded test result received.\n";
    }

    std::cout << "\nEmbedded test results: " << (embeddedPass ? "PASS" : "FAIL");
    if (!embeddedPass && firstFailedTest > 0) {
        const char* testNames[] = { "", "basic_send_receive", "specific_handler", "request_response", "integer_payload", "float_payload" };
        std::cout << " (First failed test: " << testNames[firstFailedTest] << ")";
    }
    std::cout << "\n";

    return 0;
}

#endif // BUILD_UART_TEST