#include "SongbirdUARTNode.h"

SongbirdUARTNode::SongbirdUARTNode(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::STREAM)) {
        protocol->attachStream(this);
}

SongbirdUARTNode::~SongbirdUARTNode() {
    close();
}

bool SongbirdUARTNode::begin(unsigned int baudRate) {
    Serial.begin(baudRate);
    return true;
}

void SongbirdUARTNode::updateData() {
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

void SongbirdUARTNode::close() {
    Serial.end();
}

void SongbirdUARTNode::write(const uint8_t* buffer, std::size_t length) {
    Serial.write(buffer, length);
}

std::shared_ptr<SongbirdCore> SongbirdUARTNode::getProtocol() {
    return protocol;
}

bool SongbirdUARTNode::isOpen() const {
    return Serial;
}