# Songbird Protocol - Python Implementation

A Python implementation of the Songbird communication protocol supporting both UDP and UART transport layers with reliable and unreliable delivery modes.

## Features

- **Multiple Transport Layers**: UDP and UART/Serial support
- **Flexible Delivery Modes**: 
  - RELIABLE: Streamlined protocol without sequence numbers
  - UNRELIABLE: Full featured with guaranteed delivery, retransmission, and packet ordering
- **Processing Modes**:
  - STREAM: Length-prefixed framing for serial connections
  - PACKET: Direct packet transmission for UDP
- **Advanced Features**:
  - Guaranteed delivery with automatic retransmission
  - Packet ordering and out-of-order handling
  - Missing packet timeout detection
  - Multi-remote support with per-remote handlers
  - Header-based packet routing
  - Multicast and broadcast support (UDP)

## Installation

### From Source

```bash
cd desktop_python/Songbird
pip install -e .
```

### With Development Tools

```bash
pip install -e ".[dev]"
```

## Requirements

- Python 3.7+
- pyserial >= 3.5 (for UART support)

## Quick Start

### UDP Communication

```python
from songbird import SongbirdUDP

# Create UDP instance
udp = SongbirdUDP("MyNode")

# Listen on port 8080
udp.listen(8080)

# Set remote endpoint
udp.set_remote("192.168.1.100", 8080)

# Get protocol handler
core = udp.get_protocol()

# Set a packet handler
def my_handler(packet):
    print(f"Received: {packet.get_header()}")
    data = packet.read_byte()
    print(f"Data: {data}")

core.set_header_handler(0x10, my_handler)

# Send a packet
pkt = core.create_packet(0x10)
pkt.write_byte(0x42)
core.send_packet(pkt)

# Send with guaranteed delivery
pkt2 = core.create_packet(0x20)
pkt2.write_float(3.14159)
core.send_packet(pkt2, guarantee_delivery=True)
```

### UART Communication

```python
from songbird import SongbirdUART

# Create UART instance
uart = SongbirdUART("MyNode")

# Open serial port
if uart.begin("COM3", 115200):  # Windows
# if uart.begin("/dev/ttyUSB0", 115200):  # Linux
    core = uart.get_protocol()
    
    # Wait for response
    response = core.wait_for_header(0xFF, timeout_ms=1000)
    if response:
        print("Got response!")
```

### UDP Multicast

```python
from songbird import SongbirdUDP

udp = SongbirdUDP("MulticastNode")
core = udp.get_protocol()

# Listen to multicast group
udp.listen_multicast("239.255.0.1", 1234)

# Set multicast remote
udp.set_remote("239.255.0.1", 1234)

# Send to multicast group
pkt = core.create_packet(0x01)
core.send_packet(pkt)
```

## Architecture

### Core Components

1. **IStream**: Abstract interface for communication streams
2. **SongbirdCore**: Protocol implementation handling packet encoding/decoding, ordering, and delivery
3. **SongbirdUART**: Serial/UART transport layer
4. **SongbirdUDP**: UDP transport layer with multicast support

### Packet Structure

#### UNRELIABLE Mode (default):
- **STREAM**: `[header][length][seq][guaranteed][payload]`
- **PACKET**: `[header][seq][guaranteed][payload]`

#### RELIABLE Mode:
- **STREAM**: `[header][length][payload]`
- **PACKET**: `[header][payload]`

### Packet API

```python
# Create packet
pkt = core.create_packet(0x10)

# Write data
pkt.write_byte(0x42)
pkt.write_int16(1234)
pkt.write_float(3.14)
pkt.write_bytes(b"Hello")

# Read data
value = pkt.read_byte()
number = pkt.read_int16()
pi = pkt.read_float()
data = pkt.read_bytes(5)

# Get packet info
header = pkt.get_header()
seq = pkt.get_sequence_num()
remote_ip = pkt.get_remote_ip()
remote_port = pkt.get_remote_port()
```

### Handler Types

```python
# Global handler (all packets)
def global_handler(pkt):
    print(f"Packet: {pkt.get_header()}")

core.set_read_handler(global_handler)

# Header-specific handler
def header_handler(pkt):
    print(f"Header 0x10: {pkt.get_payload()}")

core.set_header_handler(0x10, header_handler)

# Remote-specific handler
def remote_handler(pkt):
    print(f"From {pkt.get_remote_ip()}")

core.set_remote_handler("192.168.1.100", 8080, remote_handler)
```

### Blocking Wait

```python
# Wait for specific header
pkt = core.wait_for_header(0xFF, timeout_ms=1000)

# Wait for specific remote
pkt = core.wait_for_remote("192.168.1.100", 8080, timeout_ms=1000)
```

## Configuration

```python
# Set timeouts
core.set_missing_packet_timeout(100)  # milliseconds
core.set_retransmission_timeout(1000)  # milliseconds
core.set_max_retransmit_attempts(5)  # 0 = infinite

# Allow out-of-order packets (lower latency)
core.set_allow_out_of_order(True)
```

## Examples

See the `examples/` directory for complete working examples:

- `uart_master_test.py`: UART communication test suite
- `udp_client_test.py`: UDP client test suite
- `udp_multicast_server_test.py`: UDP multicast server example

## Differences from C++ Implementation

The Python implementation maintains functional parity with the C++ version while leveraging Python idioms:

- Uses Python threading instead of Boost.Asio
- Standard library `socket` for UDP
- `pyserial` for UART
- Pythonic naming (snake_case instead of camelCase)
- Context managers for resource cleanup (optional)

## Testing

Run the example tests:

```bash
# UART test (requires connected device)
python examples/uart_master_test.py

# UDP client test (requires server)
python examples/udp_client_test.py

# UDP multicast server
python examples/udp_multicast_server_test.py
```

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please ensure code follows PEP 8 style guidelines and includes appropriate tests.
