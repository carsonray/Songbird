#ifndef RUDP_SERIAL_NODE_H
#define RUDP_SERIAL_NODE_H

#include <memory>
#include <string>
#include <Arduino.h>
#include "SerialStream.h"
#include "RUDPCore.h"

class RUDPSerialNode {
public:
     RUDPSerialNode(std::string name);
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
    std::shared_ptr<SerialStream> serialStream;
    std::shared_ptr<RUDPCore> protocol;
};

#endif // MINBIT_SERIAL_NODE_H