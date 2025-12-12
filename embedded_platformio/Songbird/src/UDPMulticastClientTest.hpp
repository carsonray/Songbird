#include <Arduino.h>
#include <memory>
#include "SongbirdCore.h"
#include "SongbirdUDP.h"
#include "WiFi.h"
#define LED_BUILTIN 2

// Simple test runner that mirrors the unit tests but uses the hardware

const char *ssid = "myrouter";
const char *password = "G3tT0Th3W3b";

//Multicast configuration
const char *multicastIP = "239.255.0.1";
const uint16_t multicastPort = 1234;

// RTOS Task Handles
TaskHandle_t testsTaskHandle = NULL;
TaskHandle_t updateTaskHandler = NULL;

bool connected = false;

//UDP node object
SongbirdUDP udp("UDP Node");
//Protocol object
std::shared_ptr<SongbirdCore> core;

// RTOS task function prototypes
void testsTask(void* pvParameters);
void updateTask(void* pvParameters);

void setup() {
  pinMode(LED_BUILTIN, OUTPUT);

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

  // ID request handler
  core->setHeaderHandler(0x01, [&](std::shared_ptr<SongbirdCore::Packet> pkt) {
    Serial.println("ID request received, sending ID response");
    auto resp = core->createPacket(0x2);
    core->sendPacket(resp, true);
    connected = true;
  });

  // LED handler
  core->setHeaderHandler(0x03, [&](std::shared_ptr<SongbirdCore::Packet> pkt) {
    if (pkt->getPayloadLength() == 1) {
      if (!connected) {
        // Sends join confirmation back to server
        auto pkt1 = core->createPacket(0x2);
        core->sendPacket(pkt1, true);
        connected = true;
      }
      uint8_t cmd = pkt->readByte();
      if (cmd == 0x01) {
        Serial.println("LED ON command received");
        digitalWrite(LED_BUILTIN, HIGH);
      } else if (cmd == 0x00) {
        Serial.println("LED OFF command received");
        digitalWrite(LED_BUILTIN, LOW);
      } else {
        Serial.println("Unknown LED command received");
      }
    }
  });

  // Joins multicast group
  IPAddress multicastAddr;
  bool parsed = multicastAddr.fromString(multicastIP);
  if (!parsed) {
    Serial.print("Failed to parse remote IP string: ");
    Serial.println(multicastIP);
  }
  
  // Then join the multicast group
  if (!udp.listenMulticast(multicastAddr, multicastPort)) {
    Serial.print("Failed to join multicast group");
    while (true) {
      delay(1000);
    }
  }
  Serial.print("Listening on Multicast IP: ");
  Serial.println(multicastAddr);
  Serial.print("Listening on Multicast Port: ");
  Serial.println(multicastPort);

  // Sets multicast remote endpoint (for responses)
  udp.setRemote(multicastAddr, multicastPort);
}

void loop() {
  // Nothing to do here, all work is in RTOS tasks
}