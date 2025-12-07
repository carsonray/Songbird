#include <Arduino.h>
#include <memory>
#include "SongbirdCore.h"
#include "SongbirdUDP.h"
#include "WiFi.h"

// Simple test runner that mirrors the unit tests but uses the hardware

const char *ssid = "******";
const char *password = "******";
const uint16_t listenPort = 8080;

// RTOS Task Handles
TaskHandle_t testsTaskHandle = NULL;
TaskHandle_t updateTaskHandler = NULL;

//UDP node object
SongbirdUDP udp("UDP Node");
//Protocol object
std::shared_ptr<SongbirdCore> core;

// RTOS task function prototypes
void testsTask(void* pvParameters);
void updateTask(void* pvParameters);

void setup() {
  core = udp.getProtocol();

  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  if (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("\nWiFi Failed");
    while (1) {
      delay(1000);
    }
  } else {
    Serial.println("WiFi connected");
  }

  // Begins listening on port
  udp.listen(listenPort);

  // Create RTOS tasks with appropriate priorities
  xTaskCreatePinnedToCore(
    testsTask,           // Task function
    "Tests_Task",        // Task name
    8192,               // Increased stack size
    NULL,               // Parameters
    2,                  // Priority (higher = more important)
    &testsTaskHandle,    // Task handle
    1                   // Core (0 or 1)
  );
}

static void waitForPing()
{
  std::shared_ptr<SongbirdCore::Packet> response = nullptr;
  while (!response) {
    response = core->waitForHeader(0xFF, 1000); // Wait for ping
    core->flush();
  }
  // Sends ping
  auto pkt = core->createPacket(0xFF);
  core->sendPacket(pkt);
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
    vTaskDelay(1);
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
      vTaskDelay(1);
    }

	  if (!ok) return false;

    //Additional random packet to test handler specificity
    ok = false;

    auto pkt2 = core->createPacket(0x11);
    pkt2.writeByte(0x42);
    core->sendPacket(pkt2);

    start = millis();
    while (!ok && millis() - start < 2000) {
      vTaskDelay(1);
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

void testsTask(void* pvParameters) {
  waitForPing();

  bool pass = true;

  pass &= run_basic_send_receive();

  vTaskDelay(pdMS_TO_TICKS(200));

  pass &= run_specific_handler();

  vTaskDelay(pdMS_TO_TICKS(200));

  pass &= run_request_response();

  vTaskDelay(pdMS_TO_TICKS(200));

  pass &= run_integer_payload();

  vTaskDelay(pdMS_TO_TICKS(200));
  
  pass &= run_float_payload();

  auto pkt = core->createPacket(0x00);
  pkt.writeByte(pass ? 0x01 : 0x00);
  core->sendPacket(pkt);

  vTaskSuspend(NULL); // Suspend this task
}

void loop() {
  // Nothing to do here, all work is in RTOS tasks
}