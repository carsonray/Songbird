#ifndef RUDP_SERIAL_NODE_H
#define RUDP_SERIAL_NODE_H

#include <memory>
#include <string>
#include <Arduino.h>
#include <SoftwareSerial.h>
#include "IStream.h"
#include "SongbirdCore.h"

class SongbirdUART: public IStream {
public:
    SongbirdUART(std::string name, SoftwareSerial& serial);
    ~SongbirdUART();

    // Initialize and open the serial port
    bool begin(unsigned int baudRate);

    void updateData() override;

    // Close the serial port
    void close() override;

    void write(const uint8_t* buffer, std::size_t length) override;
    
    // UART does not support dynamic remote addressing (point-to-point)
    bool supportsRemoteWrite() const override { return false; }

    // Get the MinBiTCore protocol object
    std::shared_ptr<SongbirdCore> getProtocol();

    // Check if the serial port is open
    bool isOpen() const override;

private:
    std::shared_ptr<SongbirdCore> protocol;
    SoftwareSerial* serial;
    bool open;
};

#endif // MINBIT_SERIAL_NODE_H