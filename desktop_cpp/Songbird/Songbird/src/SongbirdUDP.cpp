#include "SongbirdUDP.h"
#include <iostream>
#include <vector>
#include <cstring>

SongbirdUDP::SongbirdUDP(std::string name)
    : socket(std::make_shared<boost::asio::ip::udp::socket>(ioContext)), protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET)), broadcastMode(false), multicastMode(false), localPort(0)
{
    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(10);
}

SongbirdUDP::~SongbirdUDP() {
    // ensure we stop async operations and threads
    close();
}

std::shared_ptr<boost::asio::ip::udp::socket> SongbirdUDP::getSocket() {
    return socket;
}

void SongbirdUDP::closeSocket() {
    asyncActive.store(false);
    if (socket && socket->is_open()) {
        boost::system::error_code ec;
        socket->close(ec);
    }
}
void SongbirdUDP::close() {
    // release work guard so run() can exit cleanly, then stop context and join thread
    ioWorkGuard.reset();
    ioContext.stop();
    if (ioThread.joinable()) ioThread.join();
    closeSocket();
}

void SongbirdUDP::startAsyncReadLoop() {
    if (!asyncActive.load() || !socket || !socket->is_open()) return;

    auto buf = std::make_shared<std::vector<uint8_t>>(ASYNC_READ_BUF);
    auto proto = protocol;
    socket->async_receive_from(boost::asio::buffer(*buf), lastRemoteEndpoint, [this, proto, buf](const boost::system::error_code& ec, std::size_t bytesTransferred) {
        if (!asyncActive.load()) return;
        if (!ec && bytesTransferred > 0) {
            //std::cout << "UDP Packet received from " << lastRemoteEndpoint.address().to_string() << ":" << lastRemoteEndpoint.port() << " (" << bytesTransferred << " bytes)" << std::endl;
            // get last remote endpoint via member
            boost::asio::ip::udp::endpoint ep = this->lastRemoteEndpoint;
            proto->parseData(buf->data(), bytesTransferred, ep.address(), ep.port());
        } else if (ec) {
            std::cerr << "UDP receive error: " << ec.message() << std::endl;
        }

        if (asyncActive.load()) {
            startAsyncReadLoop();
        }
    });
}

void SongbirdUDP::begin() {
    // create work guard to keep io_context.run() alive
    ioWorkGuard = std::make_unique<WorkGuard>(boost::asio::make_work_guard(ioContext));
    ioThread = std::thread([this]() { ioContext.run(); });
}

bool SongbirdUDP::listen(unsigned short listenPort) {
    try {
		// Close socket if already open
        closeSocket();
        socket->open(boost::asio::ip::udp::v4());
        if (listenPort != 0) {
            boost::asio::ip::udp::endpoint listenEndpoint(boost::asio::ip::udp::v4(), listenPort);
            socket->bind(listenEndpoint);
        }
        
        localPort = socket->local_endpoint().port();

        asyncActive.store(true);
        startAsyncReadLoop();
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
    listen(port);
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
    if (!socket || !socket->is_open()) return;
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
    return socket && socket->is_open();
}

boost::asio::ip::udp::endpoint SongbirdUDP::getLastRemoteEndpoint() const {
    return lastRemoteEndpoint;
}
