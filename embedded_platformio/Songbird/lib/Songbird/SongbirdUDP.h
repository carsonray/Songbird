#ifndef UDPSTREAM_H
#define UDPSTREAM_H

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

    // Sets local port to listen at
    bool listen(uint16_t port);
    // Subscribes to multicast
    bool listenMulticast(const IPAddress &addr, uint16_t port);

    // Sets remote address and port
    bool setRemote(const IPAddress &addr, uint16_t port, bool bind = false);
    // Sets broadcast mode
    void setBroadcastMode(bool broadcastMode);

    bool isBroadcast();
    bool isMulticast();
    bool isBound();

    IPAddress getRemoteIP();
    uint16_t getRemotePort();
    // Gets local port
    uint16_t getLocalPort();
    std::shared_ptr<SongbirdCore> getProtocol();

    // IStream interface
    void write(const uint8_t* buffer, std::size_t length) override;
    bool isOpen() const override;
    void close() override;
    bool supportsRemoteWrite() const override;
    void writeToRemote(const uint8_t* buffer, std::size_t length, const IPAddress& ip, uint16_t port) override;
    bool getDefaultRemote(IPAddress& outIP, uint16_t& outPort) override;

private:
    std::shared_ptr<SongbirdCore> protocol;
    AsyncUDP udp;
    bool opened;
    bool broadcastMode;
    bool multicastMode;
    bool bindMode;
    IPAddress remoteIP;
    uint16_t remotePort;
    uint16_t localPort;
};

#endif // UDPSTREAM_H
