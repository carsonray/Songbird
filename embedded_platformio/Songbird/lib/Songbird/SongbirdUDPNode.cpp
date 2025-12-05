#include "SongbirdUDPNode.h"
#include <cstring>

SongbirdUDPNode::SongbirdUDPNode(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM)), opened(false), remoteAddr(), remotePort(0)
{
    protocol->attachStream(this);
}

SongbirdUDPNode::~SongbirdUDPNode() {
    close();
}

bool SongbirdUDPNode::begin(uint16_t localPort) {
    if (!udp.listen(localPort)) return false;
    udp.onPacket([this](AsyncUDPPacket packet) {
        // Parse received data with protocol
        protocol->parseData(packet.data(), packet.length(), packet.remoteIP(), packet.remotePort());
    });
    opened = true;
    return true;
}

bool SongbirdUDPNode::setRemote(const IPAddress &addr, uint16_t port) {
    remoteAddr = addr;
    remotePort = port;

    // Attempts to connect to remote
    return udp.connect(remoteAddr, remotePort);
}

void SongbirdUDPNode::write(const uint8_t* buffer, std::size_t length) {
    if (!opened) return;
    udp.write(buffer, length);
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