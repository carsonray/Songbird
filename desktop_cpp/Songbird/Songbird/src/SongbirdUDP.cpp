#include "SongbirdUDP.h"
#include <iostream>
#include <vector>
#include <cstring>

SongbirdUDP::SongbirdUDP(std::string name)
    : socket(std::make_shared<boost::asio::ip::udp::socket>(ioContext)), protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET)), opened(false), broadcastMode(false), multicastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(10);
}

SongbirdUDP::~SongbirdUDP() {
    // ensure we stop async operations and threads
    asyncActive.store(false);
    if (socket && socket->is_open()) {
        boost::system::error_code ec;
        socket->close(ec);
    }
    ioContext.stop();
    if (ioThread.joinable()) ioThread.join();
}

std::shared_ptr<boost::asio::ip::udp::socket> SongbirdUDP::getSocket() {
    return socket;
}

void SongbirdUDP::close() {
    asyncActive.store(false);
    if (socket && socket->is_open()) {
        boost::system::error_code ec;
        socket->close(ec);
    }
    ioContext.stop();
    if (ioThread.joinable()) ioThread.join();
    opened = false;
}

void SongbirdUDP::startAsyncReadLoop() {
    if (!asyncActive.load() || !socket || !socket->is_open()) return;

    auto buf = std::make_shared<std::vector<uint8_t>>(ASYNC_READ_BUF);
    auto proto = protocol;

    socket->async_receive_from(boost::asio::buffer(*buf), lastRemoteEndpoint, [this, proto, buf](const boost::system::error_code& ec, std::size_t bytesTransferred) {
        if (!asyncActive.load()) return;
        if (!ec && bytesTransferred > 0) {
            // get last remote endpoint via member
            boost::asio::ip::udp::endpoint ep = this->lastRemoteEndpoint;
            proto->parseData(buf->data(), bytesTransferred, ep.address(), ep.port());
        }

        if (asyncActive.load()) {
            startAsyncReadLoop();
        }
    });
}

bool SongbirdUDP::begin() {
    try {
        // open UDP socket with IPv4 and bind to any port
        socket->open(boost::asio::ip::udp::v4());
        ioThread = std::thread([this]() { ioContext.run(); });
        asyncActive.store(true);
        startAsyncReadLoop();
        opened = true;
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "UDP begin error: " << e.what() << std::endl;
        return false;
    }
}

bool SongbirdUDP::listen(unsigned short listenPort, std::shared_ptr<SongbirdCore> proto) {
    try {
        boost::asio::ip::udp::endpoint listenEndpoint(boost::asio::ip::udp::v4(), listenPort);
        socket->open(boost::asio::ip::udp::v4());
        socket->bind(listenEndpoint);
        localPort = listenPort;

        if (proto) {
            protocol = proto;
            protocol->attachStream(this);
        }

        ioThread = std::thread([this]() { ioContext.run(); });
        asyncActive.store(true);
        startAsyncReadLoop();
        opened = true;
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "UDP listen error: " << e.what() << std::endl;
        return false;
    }
}

void SongbirdUDP::listenMulticast(const boost::asio::ip::address &addr, uint16_t port) {
    // For desktop, treat same as listen (multicast join not implemented here)
    multicastMode = true;
    listen(port, protocol);
}

bool SongbirdUDP::setRemote(const boost::asio::ip::address &addr, uint16_t port) {
    try {
        remoteIP = addr;
        remotePort = port;
        broadcastMode = false;
        defaultRemoteEndpoint = boost::asio::ip::udp::endpoint(addr, port);
        return true;
    }
    catch (...) {
        return false;
    }
}

void SongbirdUDP::setBroadcastMode(bool mode) {
    broadcastMode = mode;
}

boost::asio::ip::address SongbirdUDP::getRemoteIP() {
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
        if (defaultRemoteEndpoint.address().is_unspecified()) return;
        socket->async_send_to(boost::asio::buffer(buffer, length), defaultRemoteEndpoint, [](const boost::system::error_code& ec, std::size_t /*bytes*/) {
            if (ec) std::cerr << "UDP send error: " << ec.message() << std::endl;
        });
    } else {
        // Broadcast: send to 255.255.255.255 on remotePort if set
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v4::broadcast(), remotePort);
        socket->async_send_to(boost::asio::buffer(buffer, length), ep, [](const boost::system::error_code& ec, std::size_t /*bytes*/) {
            if (ec) std::cerr << "UDP broadcast error: " << ec.message() << std::endl;
        });
    }
}

bool SongbirdUDP::isOpen() const {
    return opened;
}

boost::asio::ip::udp::endpoint SongbirdUDP::getLastRemoteEndpoint() const {
    return lastRemoteEndpoint;
}
