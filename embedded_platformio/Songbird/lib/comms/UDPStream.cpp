#include "UDPStream.h"
#include <cstring>

UDPStream::UDPStream()
    : opened(false), clientMode(false), remoteAddr(), remotePort(0), rxBuffer(), rxReadPos(0)
{
}

UDPStream::~UDPStream() {
    close();
}

bool UDPStream::beginServer(uint16_t localPort) {
    if (udp.begin(localPort) == 0) return false;
    opened = true;
    clientMode = false;
    rxBuffer.clear();
    rxReadPos = 0;
    return true;
}

bool UDPStream::beginClient(const IPAddress &remoteAddr_, uint16_t remotePort_, uint16_t localPort) {
    if (localPort != 0) {
        if (udp.begin(localPort) == 0) return false;
    } else {
        // begin will allocate ephemeral local port on send
        udp.begin(localPort);
    }
    opened = true;
    clientMode = true;
    remoteAddr = remoteAddr_;
    remotePort = remotePort_;
    rxBuffer.clear();
    rxReadPos = 0;
    return true;
}

void UDPStream::setRemote(const IPAddress &addr, uint16_t port) {
    remoteAddr = addr;
    remotePort = port;
    clientMode = true;
}

void UDPStream::write(const uint8_t* buffer, std::size_t length) {
    if (!opened) return;
    if (!clientMode && remotePort == 0) return; // no remote to send to

    if (clientMode) {
        udp.beginPacket(remoteAddr, remotePort);
        udp.write(buffer, length);
        udp.endPacket();
    } else {
        // server mode: send back to last sender if known
        if (rxBuffer.size() > 0 && remotePort != 0) {
            udp.beginPacket(remoteAddr, remotePort);
            udp.write(buffer, length);
            udp.endPacket();
        }
    }
}

std::size_t UDPStream::read(uint8_t* buffer, std::size_t length) {
    if (!opened) return 0;
    if (rxReadPos >= rxBuffer.size()) {
        refillRxBuffer();
        if (rxReadPos >= rxBuffer.size()) return 0;
    }
    std::size_t avail = rxBuffer.size() - rxReadPos;
    std::size_t toRead = (length < avail) ? length : avail;
    if (toRead) {
        std::memcpy(buffer, rxBuffer.data() + rxReadPos, toRead);
        rxReadPos += toRead;
    }
    // if we consumed the buffer clear it so next read triggers refill
    if (rxReadPos >= rxBuffer.size()) {
        rxBuffer.clear();
        rxReadPos = 0;
    }
    return toRead;
}

uint8_t UDPStream::available() {
    if (!opened) return 0;
    if (rxReadPos < rxBuffer.size()) return static_cast<uint8_t>(rxBuffer.size() - rxReadPos);
    int pktSize = udp.parsePacket();
    return pktSize > 0 ? static_cast<uint8_t>(pktSize) : 0;
}

bool UDPStream::isOpen() const {
    return opened;
}

void UDPStream::close() {
    if (opened) {
        udp.stop();
        opened = false;
    }
    rxBuffer.clear();
    rxReadPos = 0;
}

void UDPStream::refillRxBuffer() {
    int pktSize = udp.parsePacket();
    if (pktSize <= 0) return;
    rxBuffer.resize(pktSize);
    int read = udp.read(rxBuffer.data(), pktSize);
    if (read > 0) {
        // record remote for server replies
        remoteAddr = udp.remoteIP();
        remotePort = udp.remotePort();
        clientMode = false; // we now know where to reply
        rxReadPos = 0;
    } else {
        rxBuffer.clear();
        rxReadPos = 0;
    }
}
