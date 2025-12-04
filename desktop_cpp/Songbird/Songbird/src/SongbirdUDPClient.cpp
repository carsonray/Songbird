#include "SongbirdUDPClient.h"

SongbirdUDPClient::SongbirdUDPClient(std::string name)
    : udpStream(std::make_shared<UDPStream>()), protocol(std::make_shared<SongbirdCore>(name))
{
    protocol->setMissingPacketTimeout(10);
    protocol->setReliabilityEnabled(true);
}

SongbirdUDPClient::~SongbirdUDPClient() {
    end();
}

bool SongbirdUDPClient::begin(const std::string& remoteAddress, unsigned short remotePort, unsigned short localPort) {
    bool ok = udpStream->beginClient(remoteAddress, remotePort, localPort, protocol);
    if (ok) {
        protocol->attachStream(udpStream);
    }
	return ok;
}

void SongbirdUDPClient::end() {
    if (udpStream) udpStream->end();
}

std::shared_ptr<SongbirdCore> SongbirdUDPClient::getProtocol() {
    return protocol;
}

bool SongbirdUDPClient::isOpen() const {
    return udpStream && udpStream->isOpen();
}
