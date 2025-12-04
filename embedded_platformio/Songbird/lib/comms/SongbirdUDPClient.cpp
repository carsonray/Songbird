#include "SongbirdUDPClient.h"
#include <Arduino.h>

SongbirdUDPClient::SongbirdUDPClient(std::string name, const IPAddress &serverAddr_, uint16_t serverPort_, uint16_t localPort_)
    : protocol(std::make_shared<SongbirdCore>(name)), udpStream(std::make_shared<UDPStream>()), serverAddr(serverAddr_), serverPort(serverPort_), localPort(localPort_)
{
    protocol->setMissingPacketTimeout(10);
}

SongbirdUDPClient::~SongbirdUDPClient() {
    end();
}

bool SongbirdUDPClient::begin() {
    bool ok = udpStream->beginClient(serverAddr, serverPort, localPort);
    if (ok) {
        protocol->attachStream(udpStream);
    }
    return ok;
}

void SongbirdUDPClient::end() {
    if (udpStream) udpStream->close();
}

std::shared_ptr<SongbirdCore> SongbirdUDPClient::getProtocol() {
    return protocol;
}

bool SongbirdUDPClient::isOpen() const {
    return udpStream && udpStream->isOpen();
}
