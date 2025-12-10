#include "SongbirdUART.h"
#include <vector>
#include <iostream>

SongbirdUART::SongbirdUART(std::string name)
    : serialPort(nullptr),
      protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM))
{
    // construct serial port with io_context
    serialPort.reset(new boost::asio::serial_port(ioContext));

    protocol->attachStream(this);
    protocol->setMissingPacketTimeout(10);
}

SongbirdUART::~SongbirdUART() {
    close();
}

bool SongbirdUART::begin(const std::string& port, unsigned int baudRate) {
    try {
        serialPort->open(port);
        serialPort->set_option(boost::asio::serial_port_base::baud_rate(baudRate));
        serialPort->set_option(boost::asio::serial_port_base::character_size(8));
        serialPort->set_option(boost::asio::serial_port_base::parity(boost::asio::serial_port_base::parity::none));
        serialPort->set_option(boost::asio::serial_port_base::stop_bits(boost::asio::serial_port_base::stop_bits::one));
        serialPort->set_option(boost::asio::serial_port_base::flow_control(boost::asio::serial_port_base::flow_control::none));

        // create work guard to keep io_context.run() alive
        ioWorkGuard = std::make_unique<WorkGuard>(boost::asio::make_work_guard(ioContext));

        // Start io thread
        ioThread = std::thread([this]() { ioContext.run(); });

        // start async read loop to notify protocol when data arrives
        asyncActive.store(true);
        startAsyncReadLoop();
        return true;
    }
    catch (boost::system::system_error& e) {
        std::cerr << "Error opening serial port: " << e.what() << std::endl;
        return false;
    }
}

void SongbirdUART::write(const uint8_t* buffer, std::size_t length) {
    if (!serialPort || !serialPort->is_open()) return;
    serialPort->async_write_some(boost::asio::buffer(buffer, length),
        [](const boost::system::error_code& ec, std::size_t /*bytesTransferred*/) {
        if (ec) {
            std::cerr << "Error writing to serial port: " << ec.message() << std::endl;
        }
    });
}

void SongbirdUART::close() {
    asyncActive.store(false);
    if (serialPort && serialPort->is_open()) {
        boost::system::error_code ec;
        serialPort->cancel(ec);
        serialPort->close(ec);
    }

    // release work guard so run() can exit cleanly, then stop context and join thread
    ioWorkGuard.reset();
    ioContext.stop();
    if (ioThread.joinable()) {
        ioThread.join();
    }
}

std::shared_ptr<SongbirdCore> SongbirdUART::getProtocol() {
    return protocol;
}

bool SongbirdUART::isOpen() const {
    return serialPort && serialPort->is_open();
}

static const std::size_t ASYNC_READ_BUF = 512;

void SongbirdUART::startAsyncReadLoop() {
    if (!serialPort || !asyncActive.load()) return;

    auto buf = std::make_shared<std::vector<uint8_t>>(ASYNC_READ_BUF);
    // Capture copies of members used inside the lambda
    auto serial = serialPort.get();
    auto proto = protocol;

    serial->async_read_some(boost::asio::buffer(*buf), [this, serial, proto, buf](const boost::system::error_code& ec, std::size_t bytesTransferred) {
        if (!asyncActive.load()) return;
        if (!ec && bytesTransferred > 0) {
            // Use public API to pass data into protocol
            proto->parseData(buf->data(), bytesTransferred);
        }

        // Reschedule next async read
        if (asyncActive.load()) {
            startAsyncReadLoop();
        }
    });
}