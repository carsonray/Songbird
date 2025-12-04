#ifndef RUDP_SERIAL_NODE_H
#define RUDP_SERIAL_NODE_H

#include <memory>
#include <string>
#include <Arduino.h>
#include "UARTStream.h"
#include "SongbirdCore.h"

class SongbirdUARTNode {
public:
     SongbirdUARTNode(std::string name);
    ~SongbirdUARTNode();

    // Initialize and open the serial port
    bool begin(unsigned int baudRate);

    // Close the serial port
    void end();

    // Get the MinBiTCore protocol object
    std::shared_ptr<SongbirdCore> getProtocol();

    // Check if the serial port is open
    bool isOpen() const;

private:
    std::shared_ptr<UARTStream> serialStream;
    std::shared_ptr<SongbirdCore> protocol;
};

#endif // MINBIT_SERIAL_NODE_H