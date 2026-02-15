#ifndef SONGBIRD_UART_H
#define SONGBIRD_UART_H

#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>
#include "IStream.h"
#include "SongbirdCore.h"

class SongbirdUART : public IStream {
public:
    SongbirdUART(std::string name);
    ~SongbirdUART();

    // Initialize and open the serial port
    bool begin(const std::string& port, unsigned int baudRate, bool silent = false);

	// Write data to the serial port
    void write(const uint8_t* buffer, std::size_t length) override;

    // Close the serial port
    void close() override;

    // Get the MinBiTCore protocol object
    std::shared_ptr<SongbirdCore> getProtocol();

    // Check if the serial port is open
    bool isOpen() const override;

    void startAsyncReadLoop();

private:
    boost::asio::io_context ioContext;
    // Serial port object (heap allocated to construct with io_context)
    std::unique_ptr<boost::asio::serial_port> serialPort;
    std::shared_ptr<SongbirdCore> protocol;
    std::thread ioThread;

    std::atomic<bool> asyncActive{false};

    // keep io_context alive while thread is running
    using WorkGuard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
    std::unique_ptr<WorkGuard> ioWorkGuard;
};

#endif // SONGBIRD_UART_H