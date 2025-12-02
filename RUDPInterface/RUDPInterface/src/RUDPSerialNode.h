#ifndef RUDP_SERIAL_NODE_H
#define RUDP_SERIAL_NODE_H

#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include "SerialStream.h"
#include "RUDPCore.h"

class RUDPSerialNode {
public:
    RUDPSerialNode(std::string name);
    ~RUDPSerialNode();

    // Initialize and open the serial port
    bool begin(const std::string& port, unsigned int baudRate);

    // Close the serial port
    void end();

    // Get the MinBiTCore protocol object
    std::shared_ptr<RUDPCore> getProtocol();

    // Check if the serial port is open
    bool isOpen() const;

private:
    boost::asio::io_context ioContext;
    std::shared_ptr<SerialStream> serialStream;
    std::shared_ptr<RUDPCore> protocol;
    std::thread ioThread;

    std::atomic<bool> asyncActive{false};
};

#endif // RUDP_SERIAL_NODE_H