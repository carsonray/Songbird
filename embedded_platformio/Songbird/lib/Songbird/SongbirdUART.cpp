#include "SongbirdUART.h"

SongbirdUART::SongbirdUART(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM, SongbirdCore::UNRELIABLE)) {
        protocol->attachStream(this);
}

SongbirdUART::~SongbirdUART() {
    close();
}

bool SongbirdUART::begin(unsigned int baudRate) {
    Serial.begin(baudRate);
    return true;
}

void SongbirdUART::updateData() {
    // Reads any available data from serial stream
    std::size_t toRead = Serial.available();
    if (Serial && toRead > 0) {
            std::vector<uint8_t> buffer(toRead);
            std::size_t bytesRead = Serial.readBytes(buffer.data(), toRead);
            if (bytesRead > 0) {
                protocol->parseData(buffer.data(), bytesRead);
            }
    }
}

void SongbirdUART::close() {
    Serial.end();
}

void SongbirdUART::write(const uint8_t* buffer, std::size_t length) {
    Serial.write(buffer, length);
}

std::shared_ptr<SongbirdCore> SongbirdUART::getProtocol() {
    return protocol;
}

bool SongbirdUART::isOpen() const {
    return Serial;
}