#include "SongbirdUDPNode.h"
#include <cstring>

SongbirdUDPNode::SongbirdUDPNode(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM)), opened(false), broadcastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(10);
}

SongbirdUDPNode::~SongbirdUDPNode() {
    close();
}

bool SongbirdUDPNode::begin() {
    udp.onPacket([this](AsyncUDPPacket packet) {
        // Parse received data with protocol
        protocol->parseData(packet.data(), packet.length(), packet.remoteIP(), packet.remotePort());
    });
    opened = true;
    return true;
}

bool SongbirdUDPNode::listen(uint16_t port) {
    multicastMode = false;
    return udp.listen(port);
}
void SongbirdUDPNode::listenMulticast(const IPAddress &addr, uint16_t port) {
    multicastMode = true;
    udp.listenMulticast(addr, port);
}

bool SongbirdUDPNode::setRemote(const IPAddress &addr, uint16_t port) {
    // Attempts to connect to remote
    remoteIP = addr;
    remotePort = port;
    broadcastMode = false;
    return udp.connect(addr, port);
}

void SongbirdUDPNode::setBroadcastMode(bool mode) {
    this->broadcastMode = mode;
}

IPAddress SongbirdUDPNode::getRemoteIP() {
    return remoteIP;
}

uint16_t SongbirdUDPNode::getRemotePort() {
    return remotePort;
}
uint16_t SongbirdUDPNode::getLocalPort() {
    return localPort;
}

bool SongbirdUDPNode::isBroadcast() {
    return broadcastMode;
}

bool SongbirdUDPNode::isMulticast() {
    return multicastMode;
}

void SongbirdUDPNode::write(const uint8_t* buffer, std::size_t length) {
    if (!opened) return;
    if (!broadcastMode) {
        udp.write(buffer, length);
    } else {
        udp.broadcast(const_cast<uint8_t*>(buffer), length);
    }
}

bool SongbirdUDPNode::isOpen() const {
    return opened;
}

void SongbirdUDPNode::close() {
    if (opened) {
        udp.close();
        opened = false;
    }
}