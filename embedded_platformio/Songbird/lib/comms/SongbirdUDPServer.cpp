#include "SongbirdUDPServer.h"
#include <Arduino.h>

SongbirdUDPServer::SongbirdUDPServer(std::string name, uint16_t listenPort)
    : protocol(std::make_shared<SongbirdCore>(name)), udpStream(std::make_shared<UDPStream>()), port(listenPort)
{
    protocol->setMissingPacketTimeout(10);
}

SongbirdUDPServer::~SongbirdUDPServer() {
    end();
}

bool SongbirdUDPServer::begin() {
    bool ok = udpStream->beginServer(port);
    if (ok) {
        protocol->attachStream(udpStream);
    }
    return ok;
}

void SongbirdUDPServer::end() {
    if (udpStream) udpStream->close();
}

std::shared_ptr<SongbirdCore> SongbirdUDPServer::getProtocol() {
    return protocol;
}

bool SongbirdUDPServer::isOpen() const {
    return udpStream && udpStream->isOpen();
}
