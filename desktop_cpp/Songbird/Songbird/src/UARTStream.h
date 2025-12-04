#ifndef UARTSTREAM_H
#define UARTSTREAM_H

#include "IStream.h"

class UARTStream : public IStream {
public:
    explicit UARTStream(std::shared_ptr<boost::asio::serial_port> serialPort);

    std::shared_ptr<boost::asio::serial_port> getSerialPort();
    void asyncWrite(const uint8_t* buffer, std::size_t length, StreamHandler handler) override;
    void asyncRead(uint8_t* buffer, std::size_t length, StreamHandler handler) override;
    bool isOpen() const override;
    void close() override;

private:
    std::shared_ptr<boost::asio::serial_port> serialPort;
};

#endif // SERIALSTREAM_H