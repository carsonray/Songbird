#ifndef SERIALSTREAM_H
#define SERIALSTREAM_H

#include "IStream.h"

class SerialStream : public IStream {
public:
    explicit SerialStream(std::shared_ptr<boost::asio::serial_port> serialPort);

    std::shared_ptr<boost::asio::serial_port> getSerialPort();
    void asyncWrite(const uint8_t* buffer, std::size_t length, StreamHandler handler) override;
    void asyncRead(uint8_t* buffer, std::size_t length, StreamHandler handler) override;
    bool isOpen() const override;
    void close() override;

private:
    std::shared_ptr<boost::asio::serial_port> serialPort;
};

#endif // SERIALSTREAM_H