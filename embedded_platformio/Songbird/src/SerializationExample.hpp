/**
 * String and Protobuf Serialization Example
 * 
 * Demonstrates how to use string and protobuf serialization with Songbird packets.
 * This example shows the API usage - integrate into your actual application as needed.
 */

#ifndef SERIALIZATION_EXAMPLE_HPP
#define SERIALIZATION_EXAMPLE_HPP

#include "SongbirdCore.h"
#include <memory>

/**
 * Example: Writing and reading strings
 */
void example_string_serialization() {
    // Create a core instance
    auto core = std::make_shared<SongbirdCore>("example", SongbirdCore::PACKET, SongbirdCore::UNRELIABLE);
    
    // Create a packet
    auto pkt = core->createPacket(0x10);
    
    // Write strings to the packet
    pkt.writeString("Hello, World!");
    pkt.writeString("");  // Empty string
    pkt.writeString("Multi-line\nString\nExample");
    
    // Send the packet (assuming stream is attached)
    // core->sendPacket(pkt);
    
    // To read strings back (e.g., on the receiving end):
    // std::string str1 = receivedPacket->readString();
    // std::string str2 = receivedPacket->readString();
    // std::string str3 = receivedPacket->readString();
}

/**
 * Example: Writing and reading protobuf messages
 * 
 * In a real application, you would:
 * 1. Define your .proto file
 * 2. Generate C++ code with protoc compiler
 * 3. Serialize your message to bytes
 * 4. Use writeProtobuf() to send
 * 5. Use readProtobuf() to receive
 * 6. Parse the bytes back to your protobuf message
 */
void example_protobuf_serialization() {
    // Create a core instance
    auto core = std::make_shared<SongbirdCore>("example", SongbirdCore::PACKET, SongbirdCore::UNRELIABLE);
    
    // Create a packet
    auto pkt = core->createPacket(0x20);
    
    // Example: Simulate serialized protobuf data
    // In real use, you would do something like:
    // MyProtoMessage msg;
    // msg.set_field1(value);
    // std::string serialized;
    // msg.SerializeToString(&serialized);
    // pkt.writeProtobuf(reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
    
    std::vector<uint8_t> protoData = {0x08, 0x96, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74};
    pkt.writeProtobuf(protoData);
    
    // Send the packet
    // core->sendPacket(pkt);
    
    // To read protobuf data back:
    // auto protoBytes = receivedPacket->readProtobuf();
    // MyProtoMessage msg;
    // msg.ParseFromArray(protoBytes.data(), protoBytes.size());
}

/**
 * Example: Mixing different data types in a single packet
 */
void example_mixed_serialization() {
    // Create a core instance
    auto core = std::make_shared<SongbirdCore>("example", SongbirdCore::PACKET, SongbirdCore::UNRELIABLE);
    
    // Create a packet with multiple data types
    auto pkt = core->createPacket(0x30);
    
    // Write sensor ID
    pkt.writeByte(0x42);
    
    // Write sensor name
    pkt.writeString("Temperature Sensor");
    
    // Write sensor value
    pkt.writeFloat(23.5f);
    
    // Write configuration as protobuf
    std::vector<uint8_t> configProto = {0x08, 0x01, 0x10, 0x0A};
    pkt.writeProtobuf(configProto);
    
    // Write timestamp
    pkt.writeInt16(12345);
    
    // Send the packet
    // core->sendPacket(pkt);
    
    // Reading back on receiver:
    // uint8_t sensorId = receivedPacket->readByte();
    // std::string sensorName = receivedPacket->readString();
    // float sensorValue = receivedPacket->readFloat();
    // auto configData = receivedPacket->readProtobuf();
    // int16_t timestamp = receivedPacket->readInt16();
}

/**
 * Example: Using with STREAM mode over UART
 */
void example_uart_with_strings() {
    // This example shows how to use strings with UART in STREAM mode
    // (STREAM mode now uses COBS encoding which handles all data transparently)
    
    // Setup code would be similar to:
    // auto uart = std::make_shared<SongbirdUART>("device");
    // uart->begin(115200);
    // auto core = uart->getProtocol();
    
    // Handler to receive string messages
    // core->setHeaderHandler(0x50, [](std::shared_ptr<SongbirdCore::Packet> pkt) {
    //     std::string message = pkt->readString();
    //     Serial.println("Received message: " + String(message.c_str()));
    // });
    
    // Send a string message
    // auto pkt = core->createPacket(0x50);
    // pkt.writeString("Hello from UART!");
    // core->sendPacket(pkt);
}

/**
 * Example: Size limits and considerations
 * 
 * - Strings are prefixed with uint16_t length (max 65535 bytes)
 * - Protobuf messages are prefixed with uint16_t length (max 65535 bytes)
 * - Total packet payload should fit in memory (typically < 1KB recommended)
 * - For large data, consider chunking or separate transfers
 */
void example_size_considerations() {
    // Good practice: Keep packets small
    auto core = std::make_shared<SongbirdCore>("example", SongbirdCore::PACKET, SongbirdCore::UNRELIABLE);
    auto pkt = core->createPacket(0x40);
    
    // Short strings are efficient
    pkt.writeString("OK");  // 2 bytes length + 2 bytes data = 4 bytes
    
    // Very long strings consume more memory
    // Be cautious with strings over 1KB in embedded systems
    
    // For large data transfers, consider:
    // 1. Chunking the data into multiple packets
    // 2. Using a separate file transfer protocol
    // 3. Compressing the data before sending
}

#endif // SERIALIZATION_EXAMPLE_HPP
