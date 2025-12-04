#ifndef SONGBIRD_UDP_SERVER_H
#define SONGBIRD_UDP_SERVER_H

#include <memory>
#include "SongbirdCore.h"
#include "UDPStream.h"

class SongbirdUDPServer {
public:
    SongbirdUDPServer(std::string name);
    ~SongbirdUDPServer();

    bool begin(unsigned short listenPort);
    void end();

    std::shared_ptr<SongbirdCore> getProtocol();
    bool isOpen() const;

private:
    std::shared_ptr<UDPStream> udpStream;
    std::shared_ptr<SongbirdCore> protocol;
};

#endif // SONGBIRD_UDP_SERVER_H
