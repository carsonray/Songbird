#include "UDPStream.h"
#include <iostream>
#include <vector>

UDPStream::UDPStream()
    : socket(std::make_shared<boost::asio::ip::udp::socket>(ioContext))
{
}

UDPStream::UDPStream(boost::asio::io_context& ctx)
    : ioContext(), socket(std::make_shared<boost::asio::ip::udp::socket>(ioContext))
{
}

std::shared_ptr<boost::asio::ip::udp::socket> UDPStream::getSocket() {
    return socket;
}

void UDPStream::asyncWrite(const uint8_t* buffer, std::size_t length, StreamHandler handler) {
    if (!socket || !socket->is_open()) return;
    if (defaultRemoteEndpoint.address().is_unspecified()) {
        // No default remote; cannot send
        return;
    }
    socket->async_send_to(boost::asio::buffer(buffer, length), defaultRemoteEndpoint, handler);
}

void UDPStream::asyncRead(uint8_t* buffer, std::size_t length, StreamHandler handler) {
    if (!socket || !socket->is_open()) return;
    socket->async_receive_from(boost::asio::buffer(buffer, length), lastRemoteEndpoint, handler);
}

bool UDPStream::isOpen() const {
    return socket && socket->is_open();
}

void UDPStream::close() {
    if (socket && socket->is_open()) {
        boost::system::error_code ec;
        socket->close(ec);
    }
}

static void startAsyncReadLoop(std::shared_ptr<UDPStream> stream, std::shared_ptr<SongbirdCore> protocol, std::atomic<bool>& active) {
    if (!stream || !active.load()) return;

    const std::size_t BUF_SZ = 2048;
    auto buf = std::make_shared<std::vector<uint8_t>>(BUF_SZ);

    stream->asyncRead(buf->data(), buf->size(), [stream, protocol, buf, &active](const boost::system::error_code& ec, std::size_t bytesTransferred) {
        if (!active.load()) return;
        if (!ec && bytesTransferred > 0) {
            protocol->appendToReadBuffer(buf->data(), bytesTransferred);
            protocol->updateData();
        }

        if (active.load()) {
            startAsyncReadLoop(stream, protocol, active);
        }
    });
}

bool UDPStream::beginClient(const std::string& remoteAddress, unsigned short remotePort, unsigned short localPort, std::shared_ptr<SongbirdCore> protocol) {
    try {
        boost::asio::ip::udp::endpoint localEndpoint(boost::asio::ip::udp::v4(), localPort);
        socket->open(boost::asio::ip::udp::v4());
        socket->bind(localEndpoint);

        defaultRemoteEndpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(remoteAddress), remotePort);

        ioThread = std::thread([this]() { ioContext.run(); });
        asyncActive.store(true);
        startAsyncReadLoop(std::static_pointer_cast<UDPStream>(shared_from_this()), protocol, asyncActive);
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "UDP client error: " << e.what() << std::endl;
        return false;
    }
}

bool UDPStream::beginServer(unsigned short listenPort, std::shared_ptr<SongbirdCore> protocol) {
    try {
        boost::asio::ip::udp::endpoint listenEndpoint(boost::asio::ip::udp::v4(), listenPort);
        socket->open(boost::asio::ip::udp::v4());
        socket->bind(listenEndpoint);

        if (protocol) {
            protocol->attachStream(std::static_pointer_cast<IStream>(shared_from_this()));
        }

        ioThread = std::thread([this]() { ioContext.run(); });
        asyncActive.store(true);
        startAsyncReadLoop(std::static_pointer_cast<UDPStream>(shared_from_this()), protocol, asyncActive);
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "UDP server error: " << e.what() << std::endl;
        return false;
    }
}

void UDPStream::end() {
    asyncActive.store(false);
    if (isOpen()) close();
    ioContext.stop();
    if (ioThread.joinable()) ioThread.join();
}
