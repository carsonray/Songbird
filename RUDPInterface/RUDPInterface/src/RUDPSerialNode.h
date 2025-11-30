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
    RUDPSerialNode(std::string name,
                   boost::asio::io_context& io_context,
                   const std::string& device);
    ~RUDPSerialNode();

    // Initialize and open the serial port
    bool begin(unsigned int baudRate);

    // Updates protocol data
    void updateDate();

    // Close the serial port
    void end();

    // Get the MinBiTCore protocol object
    std::shared_ptr<RUDPCore> getProtocol();

    // Check if the serial port is open
    bool isOpen() const;

private:
    boost::asio::io_context& io_context_;
    std::unique_ptr<std::thread> ioThread_;

    std::string device_;
    std::shared_ptr<boost::asio::serial_port> serialPort_;
    std::shared_ptr<SerialStream> serialStream; // async template wrapper

    std::shared_ptr<IStream> bufferedStream; // sync stream attached to protocol

    std::shared_ptr<RUDPCore> protocol;
    std::atomic<bool> asyncActive{false};
};

#endif // MINBIT_SERIAL_NODE_H