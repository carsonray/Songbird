#include "SongbirdUART.h"

SongbirdUART::SongbirdUART(std::string name, SoftwareSerial& serial)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM, SongbirdCore::UNRELIABLE)), serial(&serial), open(false) {
        protocol->attachStream(this);
}

SongbirdUART::~SongbirdUART() {
    close();
}

bool SongbirdUART::begin(unsigned int baudRate) {
    serial->begin(baudRate);
    open = true;
    return true;
}

void SongbirdUART::updateData() {
    // Reads any available data from serial stream
    std::size_t toRead = serial->available();
    if (open && toRead > 0) {
            std::vector<uint8_t> buffer(toRead);
            std::size_t bytesRead = serial->readBytes(buffer.data(), toRead);
            if (bytesRead > 0) {
                protocol->parseData(buffer.data(), bytesRead);
            }
    }
    
    // Update protocol timers (check for timeouts)
    protocol->update();
}

void SongbirdUART::close() {
    if (open) {
        serial->end();
        open = false;
    }
}

void SongbirdUART::write(const uint8_t* buffer, std::size_t length) {
    serial->write(buffer, length);
}

std::shared_ptr<SongbirdCore> SongbirdUART::getProtocol() {
    return protocol;
}

bool SongbirdUART::isOpen() const {
    return open;
}