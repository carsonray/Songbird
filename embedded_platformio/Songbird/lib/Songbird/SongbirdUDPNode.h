#ifndef UDPSTREAM_H
#define UDPSTREAM_H

#include <Arduino.h>
#include <memory>
#include <string>
#include "IStream.h"
#include "SongbirdCore.h"
#include <AsyncUdp.h>

class SongbirdUDPNode : public IStream {
public:
    SongbirdUDPNode(std::string name);
    ~SongbirdUDPNode() override;

    // Bind to local port
    bool begin(uint16_t localPort);

    // Sets remote address and port
    bool setRemote(const IPAddress &addr, uint16_t port);

    // IStream interface
    void write(const uint8_t* buffer, std::size_t length) override;
    bool isOpen() const override;
    void close() override;

private:
    std::shared_ptr<SongbirdCore> protocol;
    AsyncUDP udp;
    bool opened;
    IPAddress remoteAddr;
    uint16_t remotePort;
};

#endif // UDPSTREAM_H
