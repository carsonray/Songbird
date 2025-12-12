#include "SongbirdUDP.h"
#include <cstring>

SongbirdUDP::SongbirdUDP(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET, SongbirdCore::UNRELIABLE)), opened(false), broadcastMode(false), multicastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(100);
    protocol->setRetransmitTimeout(100); // Short timeout for UDP
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

bool SongbirdUDP::supportsRemoteWrite() const {
    return true;
}

void SongbirdUDP::writeToRemote(const uint8_t* buffer, std::size_t length, const IPAddress& ip, uint16_t port) {
    if (!opened) return;
    // Use writeTo to send to specific remote without changing default remote
    udp.writeTo(const_cast<uint8_t*>(buffer), length, ip, port);
}

bool SongbirdUDP::getDefaultRemote(IPAddress& outIP, uint16_t& outPort) {
    outIP = remoteIP;
    outPort = remotePort;
    return remotePort != 0; // Return true if we have a valid remote
}

void SongbirdUDP::close() {
    if (opened) {
        udp.close();
        opened = false;
    }
}