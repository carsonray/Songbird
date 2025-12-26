"""
UART Master Test

Example script demonstrating UART communication using the Songbird protocol.
Counterpart to the C++ UARTMasterTest.
"""

import time
import sys
from songbird import SongbirdUART


SERIAL_PORT = "COM6"  # Change to your serial port
SERIAL_BAUD_RATE = 115200


def wait_for_ping(core):
    """Wait for ping response from microcontroller."""
    print("Waiting for ping from microcontroller", end="", flush=True)
    time.sleep(1)  # Wait to flush initial data
    core.flush()
    
    response = None
    while not response:
        pkt = core.create_packet(0xFF)  # Ping packet
        core.send_packet(pkt)
        response = core.wait_for_header(0xFF, 1000)
        print(".", end="", flush=True)
    
    print("\nPing received from microcontroller.")


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


def run_float_test(core):
    """Test float transmission."""
    print("Test 4: Float transmission... ", end="", flush=True)
    
    test_value = 3.14159
    pkt = core.create_packet(0x30)
    pkt.write_float(test_value)
    core.send_packet(pkt)
    
    response = core.wait_for_header(0x30, 2000)
    
    if response:
        received = response.read_float()
        if abs(received - test_value) < 0.001:
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
    print("=== Songbird UART Master Test ===")
    print(f"Port: {SERIAL_PORT}")
    print(f"Baud: {SERIAL_BAUD_RATE}\n")
    
    # Initialize UART
    uart = SongbirdUART("UART Node")
    
    if not uart.begin(SERIAL_PORT, SERIAL_BAUD_RATE):
        print(f"Failed to open serial port {SERIAL_PORT}")
        return 1
    
    print(f"Opened serial port {SERIAL_PORT}")
    
    core = uart.get_protocol()
    
    try:
        # Wait for device
        wait_for_ping(core)
        
        # Run tests
        tests = [
            run_basic_send_receive,
            run_specific_handler,
            run_request_response,
            run_float_test,
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
        uart.close()