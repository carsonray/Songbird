"""
UART Master Test

Simple desktop test runner that mirrors the Arduino integration tests.
Counterpart to the C++ UARTMasterTest.
Usage: python uart_master_test.py
"""

import time
import sys
from songbird import SongbirdUART


SERIAL_PORT = "COM7"  # Change to your serial port
SERIAL_BAUD_RATE = 115200


def wait_for_ping(core):
    """Wait for ping response from microcontroller."""
    time.sleep(1)  # Wait to flush initial data
    core.flush()
    print("Waiting for ping from microcontroller", end="", flush=True)
    
    response = None
    while not response:
        pkt = core.create_packet(0xFF)  # Ping packet
        core.send_packet(pkt)
        response = core.wait_for_header(0xFF, 1000)
        core.flush()
        print(".", end="", flush=True)
    
    print("\nPing received from microcontroller.")


def run_basic_send_receive(core):
    """Test basic send and receive with read handler."""
    ok = [False]  # Use list to avoid nonlocal issues
    
    def handler(pkt):
        if pkt and pkt.get_header() == 0x10 and pkt.get_payload_length() == 1:
            if pkt.read_byte() == 0x42:
                ok[0] = True
    
    pkt = core.create_packet(0x10)
    pkt.write_byte(0x42)
    core.send_packet(pkt)
    
    core.set_read_handler(handler)
    
    start = time.time()
    while not ok[0] and (time.time() - start) < 2.0:
        time.sleep(0.005)
    
    core.set_read_handler(None)
    return ok[0]


def run_specific_handler(core):
    """Test header-specific handler."""
    ok = [False]
    
    def handler(pkt):
        if pkt and pkt.get_header() == 0x10 and pkt.get_payload_length() == 1:
            if pkt.read_byte() == 0x42:
                ok[0] = True
    
    pkt = core.create_packet(0x10)
    pkt.write_byte(0x42)
    core.send_packet(pkt)
    
    core.set_header_handler(0x10, handler)
    
    start = time.time()
    while not ok[0] and (time.time() - start) < 2.0:
        time.sleep(0.005)
    
    if not ok[0]:
        return False
    
    # Additional random packet to test handler specificity
    ok[0] = False
    
    pkt2 = core.create_packet(0x11)
    pkt2.write_byte(0x42)
    core.send_packet(pkt2)
    
    start = time.time()
    while not ok[0] and (time.time() - start) < 2.0:
        time.sleep(0.005)
    
    core.clear_header_handler(0x10)
    
    # Should NOT be ok (handler should not have been called for 0x11)
    return not ok[0]


def run_request_response(core):
    """Test request-response pattern."""
    # Send request packet
    req = core.create_packet(0x01)
    core.send_packet(req)
    
    # Wait for response packet
    response = core.wait_for_header(0x01, 2000)
    
    if response and response.get_header() == 0x01 and response.get_payload_length() == 1:
        return response.read_byte() == 0x99
    
    return False


def run_integer_payload(core):
    """Test integer payload transmission."""
    req = core.create_packet(0x30)
    req.write_int16(-12345)
    core.send_packet(req)
    
    resp = core.wait_for_header(0x30, 2000)
    
    if not resp:
        return False
    if resp.get_header() != 0x30 or resp.get_payload_length() != 2:
        return False
    
    v = resp.read_int16()
    return v == -12345


def run_float_payload(core):
    """Test float payload transmission."""
    req = core.create_packet(0x31)
    req.write_float(3.14159)
    core.send_packet(req)
    
    resp = core.wait_for_header(0x31, 2000)
    
    if not resp:
        return False
    if resp.get_header() != 0x31 or resp.get_payload_length() != 4:
        return False
    
    v = resp.read_float()
    return abs(v - 3.14159) < 0.0002


def run_string_payload(core):
    """Test string payload transmission."""
    req = core.create_packet(0x32)
    req.write_string("Hello, Songbird!")
    req.write_string("Test String 123")
    core.send_packet(req)
    
    resp = core.wait_for_header(0x32, 2000)
    
    if not resp:
        return False
    if resp.get_header() != 0x32:
        return False
    
    str1 = resp.read_string()
    str2 = resp.read_string()
    return str1 == "Hello, Songbird!" and str2 == "Test String 123"


def run_protobuf_payload(core):
    """Test protobuf payload transmission."""
    proto1 = bytes([0xAA, 0xBB, 0xCC])
    proto2 = bytes([0x01, 0x02, 0x03, 0x04])
    
    req = core.create_packet(0x33)
    req.write_protobuf(proto1)
    req.write_protobuf(proto2)
    core.send_packet(req)
    
    resp = core.wait_for_header(0x33, 2000)
    
    if not resp:
        return False
    if resp.get_header() != 0x33:
        return False
    
    recv_proto1 = resp.read_protobuf()
    recv_proto2 = resp.read_protobuf()
    return recv_proto1 == proto1 and recv_proto2 == proto2


def main():
    """Main test runner."""
    try:
        # Initialize UART
        uart = SongbirdUART("UART Node")
        core = uart.get_protocol()
        
        # Begin connection
        if not uart.begin(SERIAL_PORT, SERIAL_BAUD_RATE):
            print(f"Failed to open serial port {SERIAL_PORT}")
            return 1
    except Exception as e:
        print(f"Error initializing UART: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    wait_for_ping(core)
    
    pass_overall = True
    
    print("\nRunning basic send/receive...")
    if run_basic_send_receive(core):
        print("\nbasic_send_receive: PASS")
    else:
        print("\nbasic_send_receive: FAIL")
        pass_overall = False
    
    time.sleep(0.2)
    
    print("\nRunning specific handler test...")
    if run_specific_handler(core):
        print("\nspecific_handler: PASS")
    else:
        print("\nspecific_handler: FAIL")
        pass_overall = False
    
    time.sleep(0.2)
    
    print("\nRunning request/response test")
    if run_request_response(core):
        print("\nrequest_response: PASS")
    else:
        print("\nrequest_response: FAIL")
        pass_overall = False
    
    time.sleep(0.2)
    
    print("\nRunning integer payload test...")
    if run_integer_payload(core):
        print("\ninteger_payload: PASS")
    else:
        print("\ninteger_payload: FAIL")
        pass_overall = False
    
    time.sleep(0.2)
    
    print("\nRunning float payload test...")
    if run_float_payload(core):
        print("\nfloat_payload: PASS")
    else:
        print("\nfloat_payload: FAIL")
        pass_overall = False
    
    time.sleep(0.2)
    
    print("\nRunning string payload test...")
    if run_string_payload(core):
        print("\nstring_payload: PASS")
    else:
        print("\nstring_payload: FAIL")
        pass_overall = False
    
    time.sleep(0.2)
    
    print("\nRunning protobuf payload test...")
    if run_protobuf_payload(core):
        print("\nprotobuf_payload: PASS")
    else:
        print("\nprotobuf_payload: FAIL")
        pass_overall = False
    
    print(f"\nOverall: {'PASS' if pass_overall else 'FAIL'}")
    
    # Wait for embedded test results
    embedded_result = core.wait_for_header(0xFE, 2000)
    embedded_pass = False
    first_failed_test = 0
    
    if embedded_result and embedded_result.get_payload_length() >= 1:
        embedded_pass = bool(embedded_result.read_byte())
        if embedded_result.get_payload_length() >= 2:
            first_failed_test = embedded_result.read_byte()
        else:
            print("No first failed test index received.")
    else:
        print("No embedded test result received.")
    
    print(f"\nEmbedded test results: {'PASS' if embedded_pass else 'FAIL'}", end="")
    if not embedded_pass and first_failed_test > 0:
        test_names = ["", "basic_send_receive", "specific_handler", "request_response", 
                      "integer_payload", "float_payload", "string_payload", "protobuf_payload"]
        print(f" (First failed test: {test_names[first_failed_test]})", end="")
    print()
    
    uart.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())