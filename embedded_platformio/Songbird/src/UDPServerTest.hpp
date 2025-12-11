#include <Arduino.h>
#include <memory>
#include "SongbirdCore.h"
#include "SongbirdUDP.h"
#include "WiFi.h"

// Simple test runner that mirrors the unit tests but uses the hardware

const char *ssid = "*****";
const char *password = "*****";
const uint16_t listenPort = 8080;

//Remote endpoint configuration
const char *remoteIP = "192.168.0.187";
const uint16_t remotePort = 8080;

// RTOS Task Handles
TaskHandle_t testsTaskHandle = NULL;
TaskHandle_t updateTaskHandler = NULL;

//UDP node object
SongbirdUDP udp("UDP Node");
//Protocol object
std::shared_ptr<SongbirdCore> core;

// RTOS task function prototypes
void testsTask(void* pvParameters);

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
    Serial.print("Local IP: ");
    Serial.println(WiFi.localIP());
    Serial.print("MAC Address: ");
    Serial.println(WiFi.macAddress());
  }

  // Begins listening on port
  udp.listen(listenPort);
  Serial.print("Listening on UDP port: ");
  Serial.println(listenPort);

  // Configures remote endpoint
  IPAddress remoteAddr;
  bool remoteParsed = remoteAddr.fromString(remoteIP);
  if (!remoteParsed) {
    Serial.print("Failed to parse remote IP string: ");
    Serial.println(remoteIP);
  }
  udp.setRemote(remoteParsed ? remoteAddr : IPAddress(0, 0, 0, 0), remotePort);
  Serial.print("Remote IP: ");
  Serial.println(remoteParsed ? remoteAddr : IPAddress(0, 0, 0, 0));
  Serial.print("Remote Port: ");
  Serial.println(remotePort);

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
  Serial.print("Waiting for ping");
  std::shared_ptr<SongbirdCore::Packet> response = nullptr;
  while (!response) {
    response = core->waitForHeader(0xFF, 1000); // Wait for ping
    Serial.print(".");
  }
  Serial.println("\nPing received — sending ping response");
  // Sends ping
  auto pkt = core->createPacket(0xFF);
  core->sendPacket(pkt);
}

static bool run_basic_send_receive() {
  Serial.println("Test: basic send/receive");
  bool ok = false;
  core->setReadHandler([&](std::shared_ptr<SongbirdCore::Packet> pkt){
    if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
      ok = true;
      Serial.println("  basic_send_receive: matched packet, sending echo");
      auto pkt = core->createPacket(0x10);
      pkt.writeByte(0x42);
      core->sendPacket(pkt);
    }
  });

  unsigned long start = millis();
  while (!ok && millis() - start < 2000) {
    vTaskDelay(1);
  }
  Serial.print("  basic_send_receive: ");
  Serial.println(ok ? "PASS" : "FAIL");
  return ok;
}

static bool run_specific_handler() {
    Serial.println("Test: specific handler");
    bool ok = false;
    core->setHeaderHandler(0x10, [&](std::shared_ptr<SongbirdCore::Packet> pkt) {
        if (!pkt) return;
        if (pkt->getHeader() == 0x10 && pkt->getPayloadLength() == 1 && pkt->readByte() == 0x42) {
            ok = true;
            Serial.println("  specific_handler: matched handler, replying");
            auto pkt = core->createPacket(0x10);
            pkt.writeByte(0x42);
            core->sendPacket(pkt);
        }
    });

    unsigned long start = millis();
    while (!ok && millis() - start < 2000) {
      vTaskDelay(1);
    }

    if (!ok) {
      Serial.println("  specific_handler: initial match FAIL");
      return false;
    }

    // Additional random packet to test handler specificity
    ok = false;
    auto pkt2 = core->createPacket(0x11);
    pkt2.writeByte(0x42);
    core->sendPacket(pkt2);

    start = millis();
    while (!ok && millis() - start < 2000) {
      vTaskDelay(1);
    }

    Serial.print("  specific_handler: ");
    Serial.println(!ok ? "PASS" : "FAIL (handler matched unexpected packet)");
    return !ok;
}

static bool run_request_response() {
  Serial.println("Test: request/response");
  // Waits for request
  auto request = core->waitForHeader(0x01, 2000);
  if (!request) {
    Serial.println("  request_response: FAIL (no request)");
    return false;
  }

  // Checks data
  bool gotRequest = (request->getHeader() == 0x01 && request->getPayloadLength() == 0);

  // Sends response
  auto r = core->createPacket(0x01);
  r.writeByte(0x99);
  core->sendPacket(r);

  Serial.print("  request_response: ");
  Serial.println(gotRequest ? "PASS" : "FAIL (bad payload)");
  return gotRequest;
}

static bool run_integer_payload() {
  Serial.println("Test: integer payload");
  auto request = core->waitForHeader(0x30, 2000);
  if (!request) {
    Serial.println("  integer_payload: FAIL (no request)");
    return false;
  }
  if (request->getHeader() != 0x30 || request->getPayloadLength() != 2) {
    Serial.println("  integer_payload: FAIL (header/length mismatch)");
    return false;
  }
  int16_t v = request->readInt16();
  if (v != -12345) {
    Serial.print("  integer_payload: FAIL (value=");
    Serial.print(v);
    Serial.println(")");
    return false;
  }
  auto resp = core->createPacket(0x30);
  resp.writeInt16(-12345);
  core->sendPacket(resp);
  Serial.println("  integer_payload: PASS");
  return true;
}

static bool run_float_payload() {
  Serial.println("Test: float payload");
  auto request = core->waitForHeader(0x31, 2000);
  if (!request) {
    Serial.println("  float_payload: FAIL (no request)");
    return false;
  }
  if (request->getHeader() != 0x31 || request->getPayloadLength() != 4) {
    Serial.println("  float_payload: FAIL (header/length mismatch)");
    return false;
  }
  float v = request->readFloat();
  if (fabs(v - 3.14159f) >= 0.0002f) {
    Serial.print("  float_payload: FAIL (value=");
    Serial.print(v);
    Serial.println(")");
    return false;
  }
  auto resp = core->createPacket(0x31);
  resp.writeFloat(3.14159f);
  core->sendPacket(resp);
  Serial.println("  float_payload: PASS");
  return true;
}

void testsTask(void* pvParameters) {
  waitForPing();

  bool pass = true;

  Serial.println("Starting test sequence");
  bool r = run_basic_send_receive();
  pass &= r;

  Serial.print("Result - basic_send_receive: ");
  Serial.println(r ? "PASS" : "FAIL");

  vTaskDelay(pdMS_TO_TICKS(200));


  r = run_specific_handler();
  pass &= r;
  Serial.print("Result - specific_handler: ");
  Serial.println(r ? "PASS" : "FAIL");

  vTaskDelay(pdMS_TO_TICKS(200));


  r = run_request_response();
  pass &= r;
  Serial.print("Result - request_response: ");
  Serial.println(r ? "PASS" : "FAIL");

  vTaskDelay(pdMS_TO_TICKS(200));


  r = run_integer_payload();
  pass &= r;
  Serial.print("Result - integer_payload: ");
  Serial.println(r ? "PASS" : "FAIL");

  vTaskDelay(pdMS_TO_TICKS(200));
  

  r = run_float_payload();
  pass &= r;
  Serial.print("Result - float_payload: ");
  Serial.println(r ? "PASS" : "FAIL");

  auto pkt = core->createPacket(0x00);
  pkt.writeByte(pass ? 0x01 : 0x00);
  core->sendPacket(pkt);

  vTaskSuspend(NULL); // Suspend this task
}

void loop() {
  // Nothing to do here, all work is in RTOS tasks
}