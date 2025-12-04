#ifndef SONGBIRD_UDP_CLIENT_H
#define SONGBIRD_UDP_CLIENT_H

#include <memory>
#include <string>
#include <IPAddress.h>
#include "SongbirdCore.h"
#include "UDPStream.h"

class SongbirdUDPClient {
public:
    SongbirdUDPClient(std::string name, const IPAddress &serverAddr, uint16_t serverPort, uint16_t localPort = 0);
    ~SongbirdUDPClient();

    bool begin();
    void end();
    std::shared_ptr<SongbirdCore> getProtocol();
    bool isOpen() const;

private:
    std::shared_ptr<UDPStream> udpStream;
    std::shared_ptr<SongbirdCore> protocol;
    IPAddress serverAddr;
    uint16_t serverPort;
    uint16_t localPort;
};

#endif
