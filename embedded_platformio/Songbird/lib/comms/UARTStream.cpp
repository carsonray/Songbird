#include "UARTStream.h"

UARTStream::UARTStream() {}

void UARTStream::write(const uint8_t* buffer, std::size_t length) {
    Serial.write(buffer, length);
}

std::size_t UARTStream::read(uint8_t* buffer, std::size_t length) {
    return Serial.readBytes(buffer, length);
}

uint8_t UARTStream::available() {
    return Serial.available();
}

void UARTStream::begin(unsigned int baudRate) {
    Serial.begin(baudRate);
}

bool UARTStream::isOpen() const {
    return Serial;
}

void UARTStream::close() {
    if (Serial) {
        Serial.end();
    }
}
