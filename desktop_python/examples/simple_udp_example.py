"""
Simple UDP Example

Basic example demonstrating simple UDP communication with Songbird protocol.
"""

import time
from songbird import SongbirdUDP

def main():
    # Create two UDP nodes for demo
    print("=== Simple Songbird UDP Example ===\n")
    
    # Node 1: Server
    server = SongbirdUDP("Server")
    server.listen(9000)
    server_core = server.get_protocol()
    
    # Node 2: Client
    client = SongbirdUDP("Client")
    client.listen(9001)
    client.set_remote("127.0.0.1", 9000)
    client_core = client.get_protocol()
    
    # Set up server to echo messages
    def server_handler(pkt):
        print(f"Server received: Header={hex(pkt.get_header())}, "
              f"From={pkt.get_remote_ip()}:{pkt.get_remote_port()}")
        
        # Echo back
        response = server_core.create_packet(pkt.get_header())
        response.write_bytes(pkt.get_payload())
        response.set_remote(pkt.get_remote_ip(), pkt.get_remote_port())
        server_core.send_packet(response)
        print("Server echoed packet back")
    
    server_core.set_read_handler(server_handler)
    
    # Set up client to receive echoes
    received_count = 0
    
    def client_handler(pkt):
        nonlocal received_count
        received_count += 1
        data = pkt.read_byte()
        print(f"Client received echo: {data}\n")
    
    client_core.set_read_handler(client_handler)
    
    try:
        # Send some test packets
        print("Sending test packets...\n")
        
        for i in range(3):
            pkt = client_core.create_packet(0x10)
            pkt.write_byte(0x40 + i)
            client_core.send_packet(pkt)
            print(f"Client sent packet {i+1}")
            time.sleep(0.5)
        
        # Wait for responses
        print("\nWaiting for responses...")
        time.sleep(1)
        
        print(f"\n=== Summary ===")
        print(f"Sent: 3 packets")
        print(f"Received: {received_count} packets")
        
        if received_count == 3:
            print("SUCCESS: All packets echoed!")
        else:
            print(f"WARNING: Only {received_count}/3 packets received")
    
    finally:
        server.close()
        client.close()
        print("\nClosed connections")

if __name__ == "__main__":
    main()
