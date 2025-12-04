#include "UARTStream.h"

UARTStream::UARTStream(std::shared_ptr<boost::asio::serial_port> serialPort)
    : serialPort(std::move(serialPort)) {
}

std::shared_ptr<boost::asio::serial_port> UARTStream::getSerialPort() {
    return serialPort;
}

void UARTStream::asyncWrite(const uint8_t* buffer, std::size_t length, StreamHandler handler) {
    boost::asio::async_write(*serialPort, boost::asio::buffer(buffer, length), handler);
}

void UARTStream::asyncRead(uint8_t* buffer, std::size_t length, StreamHandler handler) {
    serialPort->async_read_some(boost::asio::buffer(buffer, length), handler);
}

bool UARTStream::isOpen() const {
    return serialPort->is_open();
}

void UARTStream::close() {
    if (serialPort->is_open()) {
        serialPort->close();
    }
}
