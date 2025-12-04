#include "SongbirdUDPServer.h"

SongbirdUDPServer::SongbirdUDPServer(std::string name)
    : udpStream(std::make_shared<UDPStream>()), protocol(std::make_shared<SongbirdCore>(name))
{
    protocol->setMissingPacketTimeout(10);
    protocol->setReliabilityEnabled(true);
}

SongbirdUDPServer::~SongbirdUDPServer() {
    end();
}

bool SongbirdUDPServer::begin(unsigned short listenPort) {
    bool ok = udpStream->beginServer(listenPort, protocol);
    if (ok) {
        protocol->attachStream(udpStream);
	}
    return ok;
}

void SongbirdUDPServer::end() {
    if (udpStream) udpStream->end();
}

std::shared_ptr<SongbirdCore> SongbirdUDPServer::getProtocol() {
    return protocol;
}

bool SongbirdUDPServer::isOpen() const {
    return udpStream && udpStream->isOpen();
}
