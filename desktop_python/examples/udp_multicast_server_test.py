"""
UDP Multicast Server Test

Example script demonstrating UDP multicast communication using the Songbird protocol.
Counterpart to the C++ UDPMulticastServerTest.
"""

import time
import sys
from songbird import SongbirdUDP


UDP_MULTICAST_IP = "239.255.0.1"
UDP_MULTICAST_PORT = 1234


def main():
    """Main server loop."""
    print("=== Songbird UDP Multicast Server Test ===")
    print(f"Multicast: {UDP_MULTICAST_IP}:{UDP_MULTICAST_PORT}\n")
    
    # Initialize UDP
    udp = SongbirdUDP("UDP Node")
    core = udp.get_protocol()
    
    # Set handler for identification messages
    def id_handler(pkt):
        remote_ip = pkt.get_remote_ip()
        print(f"New multicast member at IP address {remote_ip}")
    
    core.set_header_handler(0x02, id_handler)
    
    # Begin multicast connection
    if not udp.listen_multicast(UDP_MULTICAST_IP, UDP_MULTICAST_PORT):
        print("Failed to start multicast listener")
        return 1
    
    print(f"Listening on multicast group {UDP_MULTICAST_IP}:{UDP_MULTICAST_PORT}")
    
    # Set multicast remote
    udp.set_remote(UDP_MULTICAST_IP, UDP_MULTICAST_PORT)
    
    # Send initial identification message
    id_pkt = core.create_packet(0x01)
    core.send_packet(id_pkt)
    print("Sent identification message")
    
    # Run server loop to send LED toggle messages every second
    led_state = False
    
    try:
        while True:
            # Send LED toggle message with guaranteed delivery
            pkt = core.create_packet(0x03)
            pkt.write_byte(1 if led_state else 0)
            core.send_packet(pkt, guarantee_delivery=True)
            print(f"Sent LED toggle: {'ON' if led_state else 'OFF'}")
            
            led_state = not led_state
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    finally:
        udp.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
