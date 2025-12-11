#include "SongbirdUDP.h"
#include <cstring>

SongbirdUDP::SongbirdUDP(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET)), opened(false), broadcastMode(false), multicastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(10);
    udp.onPacket([this](AsyncUDPPacket packet) {
        // Parse received data with protocol
        protocol->parseData(packet.data(), packet.length(), packet.remoteIP(), packet.remotePort());
    });
}

SongbirdUDP::~SongbirdUDP() {
    close();
}

bool SongbirdUDP::listen(uint16_t port) {
    multicastMode = false;
    opened = true;
    return udp.listen(port);
}
bool SongbirdUDP::listenMulticast(const IPAddress &addr, uint16_t port) {
    multicastMode = true;
    opened = true;
    bool result = udp.listenMulticast(addr, port);
    return result;
}

bool SongbirdUDP::setRemote(const IPAddress &addr, uint16_t port, bool bind) {
    // Attempts to connect to remote
    remoteIP = addr;
    remotePort = port;
    broadcastMode = false;
    bindMode = bind;
    if (bind) {
        return udp.connect(addr, port);
    }
    return true;
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

bool SongbirdUDP::isBound() {
    return bindMode;
}

void SongbirdUDP::write(const uint8_t* buffer, std::size_t length) {
    if (!opened) return;
    if (!broadcastMode) {
        if (bindMode) {
            udp.write(buffer, length);
        } else {
            udp.writeTo(buffer, length, remoteIP, remotePort, TCPIP_ADAPTER_IF_STA);
        }
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