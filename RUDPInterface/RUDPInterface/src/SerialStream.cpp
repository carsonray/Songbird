#include "SerialStream.h"

SerialStream::SerialStream(std::shared_ptr<boost::asio::serial_port> serialPort)
    : serialPort(std::move(serialPort)) {
}

std::shared_ptr<boost::asio::serial_port> SerialStream::getSerialPort() {
    return serialPort;
}

void SerialStream::asyncWrite(const uint8_t* buffer, std::size_t length, StreamHandler handler) {
    boost::asio::async_write(*serialPort, boost::asio::buffer(buffer, length), handler);
}

void SerialStream::asyncRead(uint8_t* buffer, std::size_t length, StreamHandler handler) {
    serialPort->async_read_some(boost::asio::buffer(buffer, length), handler);
}

bool SerialStream::isOpen() const {
    return serialPort->is_open();
}

void SerialStream::close() {
    if (serialPort->is_open()) {
        serialPort->close();
    }
}
