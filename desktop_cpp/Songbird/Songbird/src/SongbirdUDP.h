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

    bool listen(unsigned short listenPort);
	
    bool listenMulticast(const boost::asio::ip::address &addr, uint16_t port);
    // setRemote now accepts a bind flag; if true the socket will be connected to the remote endpoint
    void setRemote(const boost::asio::ip::address &addr, uint16_t port, bool bind = false);
    void setBroadcastMode(bool mode);
    boost::asio::ip::address getRemoteIP();
    uint16_t getRemotePort();
    uint16_t getLocalPort();
    std::shared_ptr<SongbirdCore> getProtocol();
    bool isBroadcast();
    bool isMulticast();
    // Returns true if the socket has been connected to a remote (bind mode)
    bool isBound() const;

    // IStream overrides
    std::shared_ptr<boost::asio::ip::udp::socket> getSocket();
    using StreamHandler = std::function<void(const boost::system::error_code&, std::size_t)>;

    bool isOpen() const override;
    void closeSocket();
    void close() override;

    // write helper matching embedded API (sends to configured remote)
    void write(const uint8_t* buffer, std::size_t length) override;

    bool supportsRemoteWrite() const override;
    void writeToRemote(const uint8_t* buffer, std::size_t length, const boost::asio::ip::address& ip, uint16_t port) override;
    bool getDefaultRemote(boost::asio::ip::address& outIP, uint16_t& outPort) override;

    // Start internal async read loop
    void startAsyncReadLoop();

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

    // If true, socket is connected to remote and write should use send (no endpoint)
    bool bindMode{false};

    // keep io_context alive while thread is running
    using WorkGuard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
    std::unique_ptr<WorkGuard> ioWorkGuard;

    // whether the io thread / work guard has been started
    bool begun{false};

    // helper to start IO thread, close existing socket and open a new IPv4 socket
    // if reuseAddress is true, sets SO_REUSEADDR before binding
    bool prepareSocket(bool reuseAddress = false);
    
    static const std::size_t ASYNC_READ_BUF = 2048;
};

#endif // UDPSTREAM_H
