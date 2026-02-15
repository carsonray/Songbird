#include <Arduino.h>
#include <memory>
#include "SongbirdCore.h"
#include "SongbirdUART.h"

#define SERIAL_BAUD 115200

// Simple test runner that mirrors the unit tests but uses the hardware Serial
// Pico version - no FreeRTOS, simple loop-based execution

//Serial node object
SongbirdUART uart("UART Node");
//Serial server protocol object
std::shared_ptr<SongbirdCore> core;

// Test state
enum TestState {
  WAITING_FOR_PING,
  RUNNING_TESTS,
  TESTS_COMPLETE
};

TestState currentState = WAITING_FOR_PING;
uint8_t currentTest = 0;
bool testPass = true;
uint8_t firstFailedTest = 0;
unsigned long testStartTime = 0;

void setup() {
  core = uart.getProtocol();
  uart.begin(SERIAL_BAUD);
  currentState = WAITING_FOR_PING;
}

static void waitForPing()
{
  std::shared_ptr<SongbirdCore::Packet> response = nullptr;
  response = core->waitForHeader(0xFF, 1000); // Wait for ping
  if (response) {
    core->flush();
    // Sends ping
    auto pkt = core->createPacket(0xFF);
    core->sendPacket(pkt);
    currentState = RUNNING_TESTS;
    currentTest = 0;
    testStartTime = millis();
  }
}

static bool run_basic_send_receive() {
  bool ok = false;
  core->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
    if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
      ok = true;
      auto pkt = core->createPacket(0x10);
      pkt.writeByte(0x42);
      core->sendPacket(pkt);
    }
  });

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    uart.updateData();
    delay(1);
  }
  return ok;
}

static bool run_specific_handler() {
    bool ok = false;
    core->setHeaderHandler(0x10, [&](std::shared_ptr<SongbirdCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
            ok = true;
            auto pkt = core->createPacket(0x10);
            pkt.writeByte(0x42);
            core->sendPacket(pkt);
        }
        });

    unsigned long start = millis();
    while (!ok && millis() - start < 2000) {
      uart.updateData();
      delay(1);
    }

	  if (!ok) return false;

    //Additional random packet to test handler specificity
    ok = false;

    auto pkt2 = core->createPacket(0x11);
    pkt2.writeByte(0x42);
    core->sendPacket(pkt2);

    start = millis();
    while (!ok && millis() - start < 2000) {
      uart.updateData();
      delay(1);
    }

    return !ok;
}

static bool run_request_response() {
  // Waits for request
  auto request = core->waitForHeader(0x01, 2000);

  // Checks data
  bool gotRequest = (request->getHeader() == 0x01 && request->getPayloadLength() == 0);

  // Sends response
  auto r = core->createPacket(0x01);
  r.writeByte(0x99);
  core->sendPacket(r);

  return gotRequest;
}

static bool run_integer_payload() {
  auto request = core->waitForHeader(0x30, 2000);
  if (!request) return false;
  if (request->getHeader() != 0x30 || request->getPayloadLength() != 2) return false;
  int16_t v = request->readInt16();
  if (v != -12345) return false;
  auto resp = core->createPacket(0x30);
  resp.writeInt16(-12345);
  core->sendPacket(resp);
  return true;
}

static bool run_float_payload() {
  auto request = core->waitForHeader(0x31, 2000);
  if (!request) return false;
  if (request->getHeader() != 0x31 || request->getPayloadLength() != 4) return false;
  float v = request->readFloat();
  if (fabs(v - 3.14159f) >= 0.0002f) return false;
  auto resp = core->createPacket(0x31);
  resp.writeFloat(3.14159f);
  core->sendPacket(resp);
  return true;
}

static bool run_string_payload() {
  auto request = core->waitForHeader(0x32, 2000);
  if (!request) return false;
  if (request->getHeader() != 0x32) return false;
  std::string str1 = request->readString();
  std::string str2 = request->readString();
  if (str1 != "Hello, Songbird!" || str2 != "Test String 123") return false;
  auto resp = core->createPacket(0x32);
  resp.writeString("Hello, Songbird!");
  resp.writeString("Test String 123");
  core->sendPacket(resp);
  return true;
}

static bool run_protobuf_payload() {
  auto request = core->waitForHeader(0x33, 2000);
  if (!request) return false;
  if (request->getHeader() != 0x33) return false;
  std::vector<uint8_t> proto1 = request->readProtobuf();
  std::vector<uint8_t> proto2 = request->readProtobuf();
  if (proto1.size() != 3 || proto1[0] != 0xAA || proto1[1] != 0xBB || proto1[2] != 0xCC) return false;
  if (proto2.size() != 4 || proto2[0] != 0x01 || proto2[1] != 0x02 || proto2[2] != 0x03 || proto2[3] != 0x04) return false;
  auto resp = core->createPacket(0x33);
  resp.writeProtobuf(proto1);
  resp.writeProtobuf(proto2);
  core->sendPacket(resp);
  return true;
}

void runTests() {
  if (!run_basic_send_receive()) { if (firstFailedTest == 0) firstFailedTest = 1; testPass = false; }
  delay(200);

  if (!run_specific_handler()) { if (firstFailedTest == 0) firstFailedTest = 2; testPass = false; }
  delay(200);

  if (!run_request_response()) { if (firstFailedTest == 0) firstFailedTest = 3; testPass = false; }
  delay(200);

  if (!run_integer_payload()) { if (firstFailedTest == 0) firstFailedTest = 4; testPass = false; }
  delay(200);
  
  if (!run_float_payload()) { if (firstFailedTest == 0) firstFailedTest = 5; testPass = false; }
  delay(200);
  
  if (!run_string_payload()) { if (firstFailedTest == 0) firstFailedTest = 6; testPass = false; }
  delay(200);
  
  if (!run_protobuf_payload()) { if (firstFailedTest == 0) firstFailedTest = 7; testPass = false; }

  auto pkt = core->createPacket(0xFE);
  pkt.writeByte(testPass ? 0x01 : 0x00);
  pkt.writeByte(firstFailedTest);
  core->sendPacket(pkt);

  currentState = TESTS_COMPLETE;
}

void loop() {
  // Update UART data
  uart.updateData();
  
  // State machine for test execution
  switch (currentState) {
    case WAITING_FOR_PING:
      waitForPing();
      break;
      
    case RUNNING_TESTS:
      runTests();
      break;
      
    case TESTS_COMPLETE:
      // Tests are done, just keep updating UART
      delay(100);
      break;
  }
  
  delay(1);
}
