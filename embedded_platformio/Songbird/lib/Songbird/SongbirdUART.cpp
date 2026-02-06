#include "SongbirdUART.h"

SongbirdUART::SongbirdUART(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name, SongbirdCore::PACKET, SongbirdCore::UNRELIABLE)) {
        protocol->attachStream(this);
}

SongbirdUART::~SongbirdUART() {
    close();
}

bool SongbirdUART::begin(unsigned int baudRate) {
    packetSerial.setStream(&Serial);
    packetSerial.setPacketHandler([this](const uint8_t* buffer, size_t size) {
        this->onPacketReceived(buffer, size);
    });
    Serial.begin(baudRate);
    return true;
}

void SongbirdUART::updateData() {
    // PacketSerial handles reading and will call onPacketReceived when a complete packet is received
    packetSerial.update();
}

void SongbirdUART::onPacketReceived(const uint8_t* buffer, size_t size) {
    if (protocol) {
        protocol->parseData(buffer, size);
    }
}

void SongbirdUART::close() {
    Serial.end();
}

void SongbirdUART::write(const uint8_t* buffer, std::size_t length) {
    packetSerial.send(buffer, length);
}

std::shared_ptr<SongbirdCore> SongbirdUART::getProtocol() {
    return protocol;
}

bool SongbirdUART::isOpen() const {
    return Serial;
}