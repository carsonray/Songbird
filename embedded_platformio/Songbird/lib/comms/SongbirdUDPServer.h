#ifndef SONGBIRD_UDP_SERVER_H
#define SONGBIRD_SERVER_H

#include <memory>
#include <string>
#include "SongbirdCore.h"
#include "UDPStream.h"

class SongbirdUDPServer {
public:
    SongbirdUDPServer(std::string name, uint16_t listenPort);
    ~SongbirdUDPServer();

    bool begin();
    void end();
    std::shared_ptr<SongbirdCore> getProtocol();
    bool isOpen() const;

private:
    std::shared_ptr<UDPStream> udpStream;
    std::shared_ptr<SongbirdCore> protocol;
    uint16_t port;
};

#endif // RUDP_SERVER_H
