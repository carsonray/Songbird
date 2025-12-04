#ifndef UDPSTREAM_H
#define UDPSTREAM_H

#include <Arduino.h>
#include "IStream.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <vector>

class UDPStream : public IStream {
public:
    UDPStream();
    ~UDPStream() override;

    // Server mode: bind to local port and accept packets from any remote
    bool beginServer(uint16_t localPort);

    // Client mode: optionally bind local port and set remote host/port
    bool beginClient(const IPAddress &remoteAddr, uint16_t remotePort, uint16_t localPort = 0);
    void setRemote(const IPAddress &addr, uint16_t port);

    // IStream interface
    void write(const uint8_t* buffer, std::size_t length) override;
    std::size_t read(uint8_t* buffer, std::size_t length) override;
    uint8_t available() override;
    bool isOpen() const override;
    void close() override;

private:
    WiFiUDP udp;
    bool opened;
    bool clientMode;
    IPAddress remoteAddr;
    uint16_t remotePort;

    std::vector<uint8_t> rxBuffer;
    std::size_t rxReadPos;
    void refillRxBuffer();
};

#endif // UDPSTREAM_H
