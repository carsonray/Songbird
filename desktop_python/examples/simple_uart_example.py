"""
Simple UART Example

Basic example demonstrating UART communication with Songbird protocol.
Shows how to send and receive data over serial port.
"""

import time
from songbird import SongbirdUART

# Configuration - Change these to match your setup
SERIAL_PORT = "COM3"  # Windows: "COM3", Linux: "/dev/ttyUSB0"
BAUD_RATE = 115200

def main():
    print("=== Simple Songbird UART Example ===")
    print(f"Port: {SERIAL_PORT}")
    print(f"Baud: {BAUD_RATE}\n")
    
    # Create UART instance
    uart = SongbirdUART("MyDevice")
    
    # Open serial port
    if not uart.begin(SERIAL_PORT, BAUD_RATE):
        print(f"ERROR: Failed to open {SERIAL_PORT}")
        print("Please check:")
        print("  - Port name is correct")
        print("  - Device is connected")
        print("  - Port is not in use by another program")
        return
    
    print(f"✓ Opened {SERIAL_PORT}\n")
    
    # Get protocol handler
    core = uart.get_protocol()
    
    # Set up packet handler
    def packet_handler(pkt):
        header = pkt.get_header()
        print(f"Received packet with header: {hex(header)}")
        
        # Example: Read different data types
        if header == 0x10:
            value = pkt.read_byte()
            print(f"  Byte value: {value}")
        elif header == 0x20:
            value = pkt.read_float()
            print(f"  Float value: {value}")
    
    core.set_read_handler(packet_handler)
    
    try:
        print("Sending test packets...\n")
        
        # Send a simple byte packet
        pkt1 = core.create_packet(0x10)
        pkt1.write_byte(42)
        core.send_packet(pkt1)
        print("Sent: Byte packet (0x10) with value 42")
        
        time.sleep(0.5)
        
        # Send a float packet
        pkt2 = core.create_packet(0x20)
        pkt2.write_float(3.14159)
        core.send_packet(pkt2)
        print("Sent: Float packet (0x20) with value 3.14159")
        
        time.sleep(0.5)
        
        # Send with guaranteed delivery
        pkt3 = core.create_packet(0x30)
        pkt3.write_byte(99)
        core.send_packet(pkt3, guarantee_delivery=True)
        print("Sent: Guaranteed packet (0x30) with value 99")
        
        # Wait for responses
        print("\nListening for responses (press Ctrl+C to stop)...")
        
        # Keep running to receive packets
        while True:
            time.sleep(0.1)
    
    except KeyboardInterrupt:
        print("\n\nStopping...")
    
    finally:
        uart.close()
        print("Closed serial port")

if __name__ == "__main__":
    main()
