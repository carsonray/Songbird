#ifndef UDPSTREAM_H
#define UDPSTREAM_H

// SongbirdUDP is only available on ESP32 (requires AsyncUdp library)
#if defined(ESP32)

#include <Arduino.h>
#include <memory>
#include <string>
#include "IStream.h"
#include "SongbirdCore.h"
#include <AsyncUdp.h>

class SongbirdUDP : public IStream {
public:
    SongbirdUDP(std::string name);
    ~SongbirdUDP() override;

    // Start listen handler
    void begin();
    
    // Update protocol timers (call regularly in main loop)
    void update();

    // Sets local port to listen at
    bool listen(uint16_t port);
    // Subscribes to multicast
    bool listenMulticast(const IPAddress &addr, uint16_t port);

    // Sets the default endpoint address and port
    bool setEndpoint(const IPAddress &addr, uint16_t port, bool bind = false);
    // Sets broadcast mode
    void setBroadcastMode(bool broadcastMode);

    bool isBroadcast();
    bool isMulticast();
    bool isBound();

    IStream::Endpoint getEndpoint() const override;
    // Gets local port
    uint16_t getLocalPort();
    std::shared_ptr<SongbirdCore> getProtocol();

    // IStream interface
    void write(const uint8_t* buffer, std::size_t length) override;
    bool isOpen() const override;
    void close() override;
    void updateData() override { update(); }
    void write(const uint8_t* buffer, std::size_t length, const IStream::Endpoint& endpoint) override;

private:
    std::shared_ptr<SongbirdCore> protocol;
    AsyncUDP udp;
    bool opened;
    bool broadcastMode;
    bool multicastMode;
    bool bindMode;
    IStream::Endpoint endpoint;
    uint16_t localPort;
};

#endif // ESP32

#endif // UDPSTREAM_H
