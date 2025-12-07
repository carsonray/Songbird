#ifndef UDPSTREAM_H
#define UDPSTREAM_H

#include "IStream.h"
#include <boost/asio.hpp>
#include <memory>
#include <thread>
#include <atomic>
#include "SongbirdCore.h"
#include <functional>

class SongbirdUDP : public IStream {
public:
    SongbirdUDP(std::string name);
    ~SongbirdUDP();

    bool begin(unsigned short listenPort);
    bool listen(unsigned short listenPort);
    void listenMulticast(const boost::asio::ip::address &addr, uint16_t port);
    bool setRemote(const boost::asio::ip::address &addr, uint16_t port);
    void setBroadcastMode(bool mode);
    boost::asio::ip::address getRemoteIP();
    uint16_t getRemotePort();
    uint16_t getLocalPort();
    std::shared_ptr<SongbirdCore> getProtocol();
    bool isBroadcast();
    bool isMulticast();

    // IStream overrides
    std::shared_ptr<boost::asio::ip::udp::socket> getSocket();
    using StreamHandler = std::function<void(const boost::system::error_code&, std::size_t)>;

    bool isOpen() const override;
    void closeSocket();
    void close() override;

    // write helper matching embedded API (sends to configured remote)
    void write(const uint8_t* buffer, std::size_t length) override;

    // Start internal async read loop
    void startAsyncReadLoop();

    // Access last remote endpoint
    boost::asio::ip::udp::endpoint getLastRemoteEndpoint() const;

private:
    boost::asio::io_context ioContext;
    std::shared_ptr<boost::asio::ip::udp::socket> socket;
    boost::asio::ip::udp::endpoint defaultRemoteEndpoint;
    boost::asio::ip::udp::endpoint lastRemoteEndpoint;
    std::thread ioThread;
    std::atomic<bool> asyncActive{false};

    std::shared_ptr<SongbirdCore> protocol;
    bool broadcastMode{false};
    bool multicastMode{false};
    boost::asio::ip::address remoteIP;
    uint16_t remotePort{0};
    uint16_t localPort{0};

    static const std::size_t ASYNC_READ_BUF = 2048;
};

#endif // UDPSTREAM_H
