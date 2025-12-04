#ifndef UDPSTREAM_H
#define UDPSTREAM_H

#include "IStream.h"
#include <boost/asio.hpp>
#include <memory>
#include <thread>
#include <atomic>
#include "SongbirdCore.h"

class UDPStream : public IStream, public std::enable_shared_from_this<UDPStream> {
public:
    UDPStream();
    explicit UDPStream(boost::asio::io_context& ctx);

    // Begin as a client: will send to remoteAddress:remotePort and optionally bind to localPort (0 = any)
    bool beginClient(const std::string& remoteAddress, unsigned short remotePort, unsigned short localPort, std::shared_ptr<SongbirdCore> protocol);

    // Begin as a server: bind to listenPort and receive from any remote
    bool beginServer(unsigned short listenPort, std::shared_ptr<SongbirdCore> protocol);

    void end();

    std::shared_ptr<boost::asio::ip::udp::socket> getSocket();
    void asyncWrite(const uint8_t* buffer, std::size_t length, StreamHandler handler) override;
    void asyncRead(uint8_t* buffer, std::size_t length, StreamHandler handler) override;
    bool isOpen() const override;
    void close() override;

private:
    boost::asio::io_context ioContext;
    std::shared_ptr<boost::asio::ip::udp::socket> socket;
    boost::asio::ip::udp::endpoint defaultRemoteEndpoint;
    boost::asio::ip::udp::endpoint lastRemoteEndpoint;
    std::thread ioThread;
    std::atomic<bool> asyncActive{false};

    static const std::size_t ASYNC_READ_BUF = 2048;
};

#endif // UDPSTREAM_H
