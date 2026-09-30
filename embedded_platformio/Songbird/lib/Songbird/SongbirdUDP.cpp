#include "SongbirdUDP.h"

// SongbirdUDP is only available on ESP32
#if defined(ESP32)

#include <cstring>

SongbirdUDP::SongbirdUDP(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET, SongbirdCore::UNRELIABLE)), opened(false), broadcastMode(false), multicastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(100);
    protocol->setRetransmitTimeout(100); // Short timeout for UDP
    udp.onPacket([this](AsyncUDPPacket packet) {
        // Parse received data with protocol
        protocol->parseData(packet.data(), packet.length(), IStream::Endpoint{packet.remoteIP(), packet.remotePort()});
    });
}

SongbirdUDP::~SongbirdUDP() {
    close();
}

void SongbirdUDP::update() {
    // Update protocol timers (check for timeouts)
    protocol->update();
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

bool SongbirdUDP::setEndpoint(const IPAddress &addr, uint16_t port, bool bind) {
    // Attempts to connect to remote
    endpoint = new Endpoint(addr, port);
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

IStream::Endpoint SongbirdUDP::getEndpoint() const {
    return endpoint;
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
            udp.writeTo(buffer, length, endpoint.ip, endpoint.port, TCPIP_ADAPTER_IF_STA);
        }
    } else {
        udp.broadcast(const_cast<uint8_t*>(buffer), length);
    }
}

bool SongbirdUDP::isOpen() const {
    return opened;
}

void SongbirdUDP::write(const uint8_t* buffer, std::size_t length, const IStream::Endpoint& target) {
    if (!opened) return;
    if (bindMode && target == endpoint) {
        write(buffer, length);
        return;
    }
    udp.writeTo(const_cast<uint8_t*>(buffer), length, target.ip, target.port);
}

void SongbirdUDP::close() {
    if (opened) {
        udp.close();
        opened = false;
    }
}

#endif // ESP32