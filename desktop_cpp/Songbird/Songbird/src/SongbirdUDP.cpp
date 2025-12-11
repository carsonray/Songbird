#include "SongbirdUDP.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <boost/asio/post.hpp>

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

// helper to start io thread & open socket; if reuseAddress is true, caller should set reuse option before bind
bool SongbirdUDP::prepareSocket(bool reuseAddress) {
    try {
        // Start io thread & work guard if not begun
        if (!begun) {
            ioWorkGuard = std::make_unique<WorkGuard>(boost::asio::make_work_guard(ioContext));
            ioThread = std::thread([this]() { ioContext.run(); });
            begun = true;
        }

        // Close socket if already open
        closeSocket();
        socket->open(boost::asio::ip::udp::v4());

        // If requested, set reuse address option. Caller must still bind afterwards.
        if (reuseAddress) {
            socket->set_option(boost::asio::socket_base::reuse_address(true));
        }

        return true;
    }
    catch (std::exception& e) {
        std::cerr << "prepareSocket error: " << e.what() << std::endl;
        return false;
    }
}

bool SongbirdUDP::listen(unsigned short listenPort) {
    try {
        if (!prepareSocket(false)) return false;

        if (listenPort != 0) {
            boost::asio::ip::udp::endpoint listenEndpoint(boost::asio::ip::udp::v4(), listenPort);
            socket->bind(listenEndpoint);
        }

        localPort = listenPort;

        asyncActive.store(true);
        startAsyncReadLoop();
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "UDP listen error: " << e.what() << std::endl;
        return false;
    }
}

bool SongbirdUDP::listenMulticast(const boost::asio::ip::address& addr, uint16_t port) {
    try {
        // Only IPv4 multicast supported by this implementation
        if (!addr.is_v4()) {
            std::cerr << "listenMulticast: only IPv4 multicast is supported\n";
            return false;
        }

        if (!prepareSocket(true)) return false;

        // Bind to the specified port on any address (required for multicast receive)
        boost::asio::ip::udp::endpoint listenEndpoint(boost::asio::ip::udp::v4(), port);
        socket->bind(listenEndpoint);

        // update localPort after bind
        localPort = socket->local_endpoint().port();

        socket->set_option(boost::asio::ip::multicast::join_group(addr));
        
        // Disable multicast loopback
		boost::asio::ip::multicast::enable_loopback loopbackOption(false);
		socket->set_option(loopbackOption);

        multicastMode = true;

        asyncActive.store(true);
        startAsyncReadLoop();
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "UDP multicast listen error: " << e.what() << std::endl;
        return false;
    }
}

void SongbirdUDP::setRemote(const boost::asio::ip::address &addr, uint16_t port, bool bind) {
    remoteIP = addr;
    remotePort = port;
    broadcastMode = false;
    bindMode = bind;

    defaultRemoteEndpoint = boost::asio::ip::udp::endpoint(addr, port);

    if (bindMode) {
        // connect socket on the io_context thread to avoid races with async operations
        boost::asio::post(ioContext, [this, addr, port]() {
            try {
                if (!socket->is_open()) socket->open(boost::asio::ip::udp::v4());
                socket->connect(defaultRemoteEndpoint);
            } catch (std::exception &e) {
                std::cerr << "Failed to connect socket in setRemote: " << e.what() << std::endl;
            }
        });
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

bool SongbirdUDP::isBound() const {
    return bindMode;
}

void SongbirdUDP::write(const uint8_t* buffer, std::size_t length) {
    if (!socket || !socket->is_open()) return;
    if (!broadcastMode) {
        if (bindMode) {
            socket->async_send(boost::asio::buffer(buffer, length), [](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) std::cerr << "UDP send error: " << ec.message() << std::endl;
            });
            return;
        }
        else {
            socket->async_send_to(boost::asio::buffer(buffer, length), defaultRemoteEndpoint, [](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) std::cerr << "UDP send error: " << ec.message() << std::endl;
            });
        }
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
