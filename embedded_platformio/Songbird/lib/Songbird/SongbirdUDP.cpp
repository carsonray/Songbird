#include "SongbirdUDP.h"
#include <cstring>

SongbirdUDP::SongbirdUDP(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET)), opened(false), broadcastMode(false), multicastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(10);
}

SongbirdUDP::~SongbirdUDP() {
    close();
}

bool SongbirdUDP::begin() {
    udp.onPacket([this](AsyncUDPPacket packet) {
        // Parse received data with protocol
        protocol->parseData(packet.data(), packet.length(), packet.remoteIP(), packet.remotePort());
    });
    opened = true;
    return true;
}

bool SongbirdUDP::listen(uint16_t port) {
    multicastMode = false;
    return udp.listen(port);
}
void SongbirdUDP::listenMulticast(const IPAddress &addr, uint16_t port) {
    multicastMode = true;
    udp.listenMulticast(addr, port);
}

bool SongbirdUDP::setRemote(const IPAddress &addr, uint16_t port) {
    // Validate remote address to avoid accidentally setting 0.0.0.0/1.0.0.0
    if (addr == IPAddress(0, 0, 0, 0)) {
        Serial.println("SongbirdUDP::setRemote: invalid remote IP (0.0.0.0), refusing to set");
        return false;
    }

    // Attempts to connect to remote
    remoteIP = addr;
    remotePort = port;
    broadcastMode = false;
    
    return udp.connect(addr, port);
}

void SongbirdUDP::setBroadcastMode(bool mode) {
    this->broadcastMode = mode;
}

IPAddress SongbirdUDP::getRemoteIP() {
    return remoteIP;
}

uint16_t SongbirdUDP::getRemotePort() {
    return remotePort;
}
uint16_t SongbirdUDP::getLocalPort() {
    return localPort;
}
std::shared_ptr<SongbirdCore> SongbirdUDP::getProtocol() {
    return protocol;
}

bool SongbirdUDP::isBroadcast() {
    return broadcastMode;
}

bool SongbirdUDP::isMulticast() {
    return multicastMode;
}

void SongbirdUDP::write(const uint8_t* buffer, std::size_t length) {
    if (!opened) return;
    if (!broadcastMode) {
        udp.write(buffer, length);
    } else {
        udp.broadcast(const_cast<uint8_t*>(buffer), length);
    }
}

bool SongbirdUDP::isOpen() const {
    return opened;
}

void SongbirdUDP::close() {
    if (opened) {
        udp.close();
        opened = false;
    }
}