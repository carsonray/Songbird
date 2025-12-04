#include "SongbirdUARTNode.h"

SongbirdUARTNode::SongbirdUARTNode(std::string name)
    : protocol(std::make_shared<SongbirdCore>(name)),
      serialStream(std::make_shared<UARTStream>()){
        protocol->setMissingPacketTimeout(10);
}

SongbirdUARTNode::~SongbirdUARTNode() {
    end();
}

bool SongbirdUARTNode::begin(unsigned int baudRate) {
    serialStream->begin(baudRate);
    protocol->attachStream(serialStream);
    return true;
}

void SongbirdUARTNode::end() {
    serialStream->close();
}

std::shared_ptr<SongbirdCore> SongbirdUARTNode::getProtocol() {
    return protocol;
}

bool SongbirdUARTNode::isOpen() const {
    return serialStream && serialStream->isOpen();
}