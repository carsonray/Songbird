#include <Arduino.h>
#include <memory>
#include "RUDPCore.h"
#include "SerialStream.h"

// Simple test runner that mirrors the unit tests but uses the hardware Serial
// as the transport. Requires wiring TX->RX for loopback or a partner device
// that echoes/responses. The runner prints PASS/FAIL to Serial.

static void waitForUser()
{
  Serial.println("Connect TX->RX for loopback (or attach partner). Press any key to start.");
  while (!Serial.available()) {
    delay(10);
  }
  // drain
  while (Serial.available()) Serial.read();
}

static bool run_basic_send_receive(std::shared_ptr<RUDPCore> core) {
  bool ok = false;
  core->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
      ok = true;
    }
  });

  auto pkt = core->createPacket(0x10);
  pkt.writeByte(0x42);
  core->sendPacket(pkt);

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    core->updateData();
    delay(5);
  }
  return ok;
}

static bool run_integer_payload(std::shared_ptr<RUDPCore> core) {
  bool ok = false;
  core->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x30 && pkt->getPayloadLength() == 2) {
      int16_t v = pkt->readInt16();
      if (v == -12345) ok = true;
    }
  });

  auto p = core->createPacket(0x30);
  p.writeInt16(static_cast<int16_t>(-12345));
  core->sendPacket(p);

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    core->updateData();
    delay(5);
  }
  return ok;
}

static bool run_float_payload(std::shared_ptr<RUDPCore> core) {
  bool ok = false;
  core->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == 0x31 && pkt->getPayloadLength() == 4) {
      float v = pkt->readFloat();
      if (fabs(v - 3.14159f) < 0.0002f) ok = true;
    }
  });

  auto p = core->createPacket(0x31);
  p.writeFloat(3.14159f);
  core->sendPacket(p);

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    core->updateData();
    delay(5);
  }
  return ok;
}

static bool run_request_response(std::shared_ptr<RUDPCore> core) {
  const uint8_t REQ = 0x01;
  const uint8_t RESP = 0x02;
  bool gotResponse = false;

  // If we receive a REQ, reply with RESP (this simulates the partner)
  core->setReadHandler([&](std::shared_ptr<RUDPCore::Packet> pkt){
    if (pkt->getHeader() == REQ) {
      auto r = core->createPacket(RESP);
      r.writeByte(0x99);
      core->sendPacket(r);
    }
    if (pkt->getHeader() == RESP) {
      if (pkt->getPayloadLength() >= 1 && pkt->readByte() == 0x99) gotResponse = true;
    }
  });

  auto req = core->createPacket(REQ);
  core->sendPacket(req);

  unsigned long start = millis();
  while (!gotResponse && millis() - start < 2000) {
    core->updateData();
    delay(5);
  }
  return gotResponse;
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("RUDPCore Serial Integration Tests");

  waitForUser();

  auto serialStream = std::make_shared<SerialStream>();
  auto core = std::make_shared<RUDPCore>("HW");
  core->attachStream(serialStream);

  bool pass = true;

  Serial.println("Running basic send/receive...");
  if (run_basic_send_receive(core)) Serial.println("basic_send_receive: PASS"); else { Serial.println("basic_send_receive: FAIL"); pass = false; }

  delay(200);
  Serial.println("Running integer payload test...");
  if (run_integer_payload(core)) Serial.println("integer_payload: PASS"); else { Serial.println("integer_payload: FAIL"); pass = false; }

  delay(200);
  Serial.println("Running float payload test...");
  if (run_float_payload(core)) Serial.println("float_payload: PASS"); else { Serial.println("float_payload: FAIL"); pass = false; }

  delay(200);
  Serial.println("Running request/response test (local echo)...");
  if (run_request_response(core)) Serial.println("request_response: PASS"); else { Serial.println("request_response: FAIL"); pass = false; }

  Serial.print("Overall: ");
  Serial.println(pass ? "PASS" : "FAIL");

  Serial.println("Tests complete. Halting.");
}

void loop() {
  // Halt
  delay(1000);
}