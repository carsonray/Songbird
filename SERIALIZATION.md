# String and Protobuf Serialization

This document describes the string and protobuf serialization features added to the Songbird protocol across all platforms (embedded C++, desktop C++, and Python).

## Overview

The Packet class now supports convenient methods for serializing and deserializing strings and protobuf messages. Both use length-prefixed encoding (uint16_t = 2 bytes) to handle variable-length data.

## String Serialization

### C++ API

```cpp
// Writing strings
auto pkt = core->createPacket(0x10);
pkt.writeString("Hello, World!");
pkt.writeString("");  // Empty strings are supported
pkt.writeString("Multi\nLine\nString");

// Reading strings
auto received = core->waitForHeader(0x10, 1000);
std::string str1 = received->readString();
std::string str2 = received->readString();
std::string str3 = received->readString();
```

### Python API

```python
# Writing strings
pkt = core.create_packet(0x10)
pkt.write_string("Hello, World!")
pkt.write_string("")  # Empty strings are supported
pkt.write_string("Multi\nLine\nString")

# Reading strings
received = core.wait_for_header(0x10, 1000)
str1 = received.read_string()
str2 = received.read_string()
str3 = received.read_string()
```

### String Format

- **Encoding**: UTF-8
- **Length prefix**: uint16_t (big-endian, 2 bytes)
- **Max length**: 65,535 bytes
- **Wire format**: `[length_hi][length_lo][...string bytes...]`

## Protobuf Serialization

Protobuf (Protocol Buffers) is a language-neutral, platform-neutral extensible mechanism for serializing structured data. The Songbird protocol provides convenient methods to embed protobuf messages in packets.

### C++ API

```cpp
// Writing protobuf data
auto pkt = core->createPacket(0x20);

// Option 1: From vector
std::vector<uint8_t> protoData = {0x08, 0x96, 0x01, ...};
pkt.writeProtobuf(protoData);

// Option 2: From buffer
uint8_t buffer[] = {0x08, 0x96, 0x01, ...};
pkt.writeProtobuf(buffer, sizeof(buffer));

// Reading protobuf data
auto received = core->waitForHeader(0x20, 1000);
std::vector<uint8_t> protoData = received->readProtobuf();
```

### Python API

```python
# Writing protobuf data
pkt = core.create_packet(0x20)
proto_data = b'\x08\x96\x01...'
pkt.write_protobuf(proto_data)

# Reading protobuf data
received = core.wait_for_header(0x20, 1000)
proto_data = received.read_protobuf()
```

### Using with Real Protobuf Messages

#### C++ Example with protobuf library

```cpp
#include <google/protobuf/message.h>
#include "my_messages.pb.h"  // Generated from your .proto file

// Sending a protobuf message
MyMessage msg;
msg.set_name("sensor_01");
msg.set_value(42.5);

std::string serialized;
msg.SerializeToString(&serialized);

auto pkt = core->createPacket(0x30);
pkt.writeProtobuf(reinterpret_cast<const uint8_t*>(serialized.data()), 
                  serialized.size());
core->sendPacket(pkt);

// Receiving a protobuf message
auto received = core->waitForHeader(0x30, 1000);
auto protoData = received->readProtobuf();

MyMessage receivedMsg;
receivedMsg.ParseFromArray(protoData.data(), protoData.size());

std::cout << "Name: " << receivedMsg.name() << std::endl;
std::cout << "Value: " << receivedMsg.value() << std::endl;
```

#### Python Example with protobuf library

```python
from my_messages_pb2 import MyMessage  # Generated from your .proto file

# Sending a protobuf message
msg = MyMessage()
msg.name = "sensor_01"
msg.value = 42.5

serialized = msg.SerializeToString()

pkt = core.create_packet(0x30)
pkt.write_protobuf(serialized)
core.send_packet(pkt)

# Receiving a protobuf message
received = core.wait_for_header(0x30, 1000)
proto_data = received.read_protobuf()

received_msg = MyMessage()
received_msg.ParseFromString(proto_data)

print(f"Name: {received_msg.name}")
print(f"Value: {received_msg.value}")
```

### Protobuf Format

- **Length prefix**: uint16_t (big-endian, 2 bytes)
- **Max length**: 65,535 bytes
- **Wire format**: `[length_hi][length_lo][...protobuf bytes...]`

## Mixed Data Types

You can mix strings, protobuf messages, and other data types in a single packet:

```cpp
auto pkt = core->createPacket(0x40);
pkt.writeByte(0x01);              // Sensor ID
pkt.writeString("Temperature");   // Sensor name
pkt.writeFloat(23.5f);            // Current value
pkt.writeProtobuf(configData);    // Configuration (protobuf)
pkt.writeInt16(1234);             // Timestamp

// Reading maintains the same order
uint8_t id = received->readByte();
std::string name = received->readString();
float value = received->readFloat();
auto config = received->readProtobuf();
int16_t timestamp = received->readInt16();
```

## Size Considerations

### Limits

- **String max length**: 65,535 bytes (uint16_t limit)
- **Protobuf max length**: 65,535 bytes (uint16_t limit)
- **Recommended packet size**: < 1 KB for embedded systems
- **Overhead**: 2 bytes per string/protobuf (length prefix)

### Best Practices

1. **Keep packets small**: Especially important for embedded systems with limited RAM
2. **Use appropriate data types**: Don't use strings when a fixed-size type would work
3. **Consider compression**: For large data, compress before sending
4. **Chunk large data**: Split data > 1KB into multiple packets
5. **Test memory usage**: Monitor heap usage in embedded environments

### Memory Usage Examples

```cpp
// Efficient (9 bytes total)
pkt.writeString("OK");      // 2 + 2 = 4 bytes
pkt.writeByte(status);      // 1 byte
pkt.writeFloat(value);      // 4 bytes

// Less efficient (1026 bytes total)
std::string largeData(1024, 'x');  // 1KB string
pkt.writeString(largeData); // 2 + 1024 = 1026 bytes
```

## Compatibility

All three platforms implement identical serialization:

- ✅ Embedded C++ (ESP32, Arduino)
- ✅ Desktop C++ (Windows, Linux, macOS)  
- ✅ Python 3.x

The wire format is identical, so packets can be exchanged between any platform combination.

## Examples

### Embedded (ESP32)
See: `embedded_platformio/Songbird/src/SerializationExample.hpp`

### Python
See: `desktop_python/examples/serialization_example.py`

Run the Python example:
```bash
cd desktop_python
python examples/serialization_example.py
```

### Unit Tests

Tests are included in:
- `embedded_platformio/Songbird/test/embedded/test_protocol/test_protocol.cpp`
  - `test_string_serialization()`
  - `test_protobuf_serialization()`

## Wire Protocol Details

### String Packet Structure
```
[Header][Seq][Guaranteed][Length_Hi][Length_Lo][String_Bytes...]
   1B     1B      1B          1B         1B      variable
```

### Protobuf Packet Structure
```
[Header][Seq][Guaranteed][Length_Hi][Length_Lo][Protobuf_Bytes...]
   1B     1B      1B          1B         1B      variable
```

### Example Wire Format

Sending string "Hi":
```
Header:  0x50
Seq:     0x01
Guar:    0x00
Len_Hi:  0x00
Len_Lo:  0x02
Data:    'H' 'i'
```

With STREAM mode (COBS encoded):
```
[COBS_encoded([0x50][0x01][0x00][0x00][0x02]['H']['i'])][0x00]
```

## Error Handling

- **Empty strings/protobufs**: Supported, transmitted as length=0
- **Oversized data**: Will be truncated at 65,535 bytes
- **UTF-8 errors (Python)**: `read_string()` uses `errors='replace'` to handle invalid UTF-8
- **Insufficient data**: Returns empty string/bytes if packet ends prematurely

## Migration Guide

If you're currently using raw bytes for strings:

### Before
```cpp
std::string msg = "Hello";
pkt.writeBytes(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
// Receiver needs to know the exact length!
```

### After
```cpp
pkt.writeString("Hello");
// Receiver can decode without knowing length in advance
std::string msg = received->readString();
```

## Related Documentation

- [COBS Encoding](README_COBS.md) - Used for STREAM mode framing
- [Protocol Specification](README_PROTOCOL.md) - Overall protocol details
- [Packet Mode vs Stream Mode](README_MODES.md) - When to use each mode
