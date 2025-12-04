#ifndef SONGBIRD_UART_NODE_H
#define SONGBIRD_UART_NODE_H

#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include "UARTStream.h"
#include "SongbirdCore.h"

class SongbirdUARTNode {
public:
    SongbirdUARTNode(std::string name);
    ~SongbirdUARTNode();

    // Initialize and open the serial port
    bool begin(const std::string& port, unsigned int baudRate);

    // Close the serial port
    void end();

    // Get the MinBiTCore protocol object
    std::shared_ptr<SongbirdCore> getProtocol();

    // Check if the serial port is open
    bool isOpen() const;

private:
    boost::asio::io_context ioContext;
    std::shared_ptr<UARTStream> serialStream;
    std::shared_ptr<SongbirdCore> protocol;
    std::thread ioThread;

    std::atomic<bool> asyncActive{false};
};

#endif // RUDP_SERIAL_NODE_H