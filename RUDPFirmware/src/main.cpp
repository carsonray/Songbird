#include <Arduino.h>
#include <memory>
#include "RUDPCore.h"
#include "RUDPSerialNode.h"
#include "SerialStream.h"

#define SERIAL_BAUD 115200

// Simple test runner that mirrors the unit tests but uses the hardware Serial
// as the transport. Requires wiring TX->RX for loopback or a partner device
// that echoes/responses. The runner prints PASS/FAIL to Serial.

//Serial node object
RUDPSerialNode interface("Middleware Interface");
//Serial server protocol object
std::shared_ptr<RUDPCore> interfaceData;

static void waitForPing()
{
  std::shared_ptr<RUDPCore::Packet> response = nullptr;
  while (!response) {
    response = interfaceData->waitForHeader(0xFF, 1000); // Wait for ping
    interfaceData->flush();
  }
  // Sends ping
  auto pkt = interfaceData->createPacket(0xFF);
  interfaceData->sendPacket(pkt);
}

static bool run_basic_send_receive() {
  bool ok = false;
  interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
      ok = true;
      auto pkt = interfaceData->createPacket(0x10);
      pkt.writeByte(0x42);
      interfaceData->sendPacket(pkt);
    }
  });

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    interfaceData->updateData();
    delay(5);
  }
  return ok;
}

static bool run_specific_handler() {
    bool ok = false;
    interfaceData->setResponseHandler(0x10, [&](std::shared_ptr<RUDPCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
            ok = true;
            auto pkt = interfaceData->createPacket(0x10);
            pkt.writeByte(0x42);
            interfaceData->sendPacket(pkt);
        }
        });

    unsigned long start = millis();
    while (!ok && millis() - start < 2000) {
      interfaceData->updateData();
      delay(5);
    }

	  if (!ok) return false;

    //Additional random packet to test handler specificity
    ok = false;

    auto pkt2 = interfaceData->createPacket(0x11);
    pkt2.writeByte(0x42);
    interfaceData->sendPacket(pkt2);

    start = millis();
    while (!ok && millis() - start < 2000) {
      interfaceData->updateData();
      delay(5);
    }

    return !ok;
}

static bool run_request_response() {
  bool gotRequest = false;

  // If we receive a REQ, reply with RESP (this simulates the partner)
  interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x01 && pkt->getPayloadLength() == 0) {
      gotRequest = true;
      auto r = interfaceData->createPacket(0x01);
      r.writeByte(0x99);
      interfaceData->sendPacket(r);
    }
  });

  std::shared_ptr<RUDPCore::Packet> response = nullptr;
  while (!response) {
    interfaceData->waitForHeader(0x01, 1000); // Send request
    delay(5);
  }

  return gotRequest;
}

static bool run_integer_payload() {
  bool ok = false;
  interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x30 && pkt->getPayloadLength() == 2) {
      int16_t v = pkt->readInt16();
      if (v == -12345) ok = true;
      auto p = interfaceData->createPacket(0x30);
      p.writeInt16(static_cast<int16_t>(-12345));
      interfaceData->sendPacket(p);
    }
  });

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    interfaceData->updateData();
    delay(5);
  }
  return ok;
}

static bool run_float_payload() {
  bool ok = false;
  interfaceData->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x31 && pkt->getPayloadLength() == 4) {
      float v = pkt->readFloat();
      if (fabs(v - 3.14159f) < 0.0002f) ok = true;
      auto p = interfaceData->createPacket(0x31);
      p.writeFloat(3.14159f);
      interfaceData->sendPacket(p);
    }
  });

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    interfaceData->updateData();
    delay(5);
  }
  return ok;
}

void setup() {
  interfaceData = interface.getProtocol();
  interface.begin(SERIAL_BAUD);

  waitForPing();

  bool pass = true;

  pass &= run_basic_send_receive();

  delay(200);

  pass &= run_specific_handler();

  delay(200);

  pass &= run_request_response();

  delay(200);

  pass &= run_integer_payload();

  delay(200);
  
  pass &= run_float_payload();

  delay(200);

  auto pkt = interfaceData->createPacket(0x00);
  pkt.writeByte(pass ? 0x01 : 0x00);
  interfaceData->sendPacket(pkt);
}

void loop() {
  // Halt
  delay(1000);
}