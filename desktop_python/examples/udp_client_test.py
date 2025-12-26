"""
UDP Client Test

Example script demonstrating UDP communication using the Songbird protocol.
Counterpart to the C++ UDPClientTest.
"""

import time
import sys
from songbird import SongbirdUDP


UDP_REMOTE_ADDR = "192.168.0.114"  # Change to your remote address
UDP_REMOTE_PORT = 8080
UDP_LOCAL_PORT = 8080


def wait_for_ping(core):
    """Wait for ping response from remote."""
    print("Waiting for ping from remote", end="", flush=True)
    
    response = None
    while not response:
        pkt = core.create_packet(0xFF)  # Ping packet
        core.send_packet(pkt)
        response = core.wait_for_header(0xFF, 1000)
        print(".", end="", flush=True)
    
    print("\nPing received from remote.")


def run_basic_send_receive(core):
    """Test basic send and receive."""
    print("Test 1: Basic send/receive... ", end="", flush=True)
    
    ok = False
    
    def handler(pkt):
        nonlocal ok
        if pkt.get_header() == 0x10 and pkt.get_payload_length() == 1:
            if pkt.read_byte() == 0x42:
                ok = True
    
    core.set_read_handler(handler)
    
    pkt = core.create_packet(0x10)
    pkt.write_byte(0x42)
    core.send_packet(pkt)
    
    start = time.time()
    while not ok and (time.time() - start) < 2.0:
        time.sleep(0.005)
    
    core.set_read_handler(None)
    
    if ok:
        print("PASSED")
    else:
        print("FAILED")
    
    return ok


def run_specific_handler(core):
    """Test header-specific handler."""
    print("Test 2: Specific handler... ", end="", flush=True)
    
    ok = False
    
    def handler(pkt):
        nonlocal ok
        if pkt.get_header() == 0x10 and pkt.get_payload_length() == 1:
            if pkt.read_byte() == 0x42:
                ok = True
    
    core.set_header_handler(0x10, handler)
    
    pkt = core.create_packet(0x10)
    pkt.write_byte(0x42)
    core.send_packet(pkt)
    
    start = time.time()
    while not ok and (time.time() - start) < 2.0:
        time.sleep(0.005)
    
    if not ok:
        print("FAILED (1st packet)")
        return False
    
    # Test that handler is specific to header 0x10
    ok = False
    pkt2 = core.create_packet(0x11)
    pkt2.write_byte(0x42)
    core.send_packet(pkt2)
    
    start = time.time()
    while not ok and (time.time() - start) < 2.0:
        time.sleep(0.005)
    
    core.clear_header_handler(0x10)
    
    if not ok:
        print("PASSED")
        return True
    else:
        print("FAILED (2nd packet should not trigger)")
        return False


def run_request_response(core):
    """Test request-response pattern."""
    print("Test 3: Request/response... ", end="", flush=True)
    
    pkt = core.create_packet(0x20)
    pkt.write_byte(0x05)
    core.send_packet(pkt)
    
    response = core.wait_for_header(0x20, 2000)
    
    if response and response.get_payload_length() == 1:
        value = response.read_byte()
        if value == 0x0A:  # Expected: 0x05 * 2
            print("PASSED")
            return True
    
    print("FAILED")
    return False


def run_remote_response(core):
    """Test remote-specific response."""
    print("Test 4: Remote response... ", end="", flush=True)
    
    pkt = core.create_packet(0x50)
    pkt.write_byte(0x77)
    core.send_packet(pkt)
    
    response = core.wait_for_remote(UDP_REMOTE_ADDR, UDP_REMOTE_PORT, 2000)
    
    if response and response.get_header() == 0x50:
        if response.read_byte() == 0x77:
            print("PASSED")
            return True
    
    print("FAILED")
    return False


def run_guaranteed_delivery(core):
    """Test guaranteed delivery."""
    print("Test 5: Guaranteed delivery... ", end="", flush=True)
    
    ok = False
    
    def handler(pkt):
        nonlocal ok
        if pkt.get_header() == 0x40:
            ok = True
    
    core.set_header_handler(0x40, handler)
    
    pkt = core.create_packet(0x40)
    pkt.write_byte(0x99)
    core.send_packet(pkt, guarantee_delivery=True)
    
    start = time.time()
    while not ok and (time.time() - start) < 3.0:
        time.sleep(0.005)
    
    core.clear_header_handler(0x40)
    
    if ok:
        print("PASSED")
    else:
        print("FAILED")
    
    return ok


def main():
    """Main test runner."""
    print("=== Songbird UDP Client Test ===")
    print(f"Remote: {UDP_REMOTE_ADDR}:{UDP_REMOTE_PORT}")
    print(f"Local port: {UDP_LOCAL_PORT}\n")
    
    # Initialize UDP
    udp = SongbirdUDP("UDP Node")
    
    if not udp.listen(UDP_LOCAL_PORT):
        print(f"Failed to bind to port {UDP_LOCAL_PORT}")
        return 1
    
    print(f"Listening on port {UDP_LOCAL_PORT}")
    
    # Set remote endpoint
    udp.set_remote(UDP_REMOTE_ADDR, UDP_REMOTE_PORT)
    
    core = udp.get_protocol()
    
    try:
        # Wait for remote
        wait_for_ping(core)
        
        # Run tests
        tests = [
            run_basic_send_receive,
            run_specific_handler,
            run_request_response,
            run_remote_response,
            run_guaranteed_delivery,
        ]
        
        results = []
        for test in tests:
            results.append(test(core))
            time.sleep(0.1)
        
        # Summary
        print("\n=== Test Summary ===")
        passed = sum(results)
        total = len(results)
        print(f"Passed: {passed}/{total}")
        
        if passed == total:
            print("All tests PASSED!")
            return 0
        else:
            print(f"{total - passed} test(s) FAILED")
            return 1
    
    finally:
        udp.close()