"""
String and Protobuf Serialization Example

Demonstrates how to use string and protobuf serialization with Songbird packets.
"""

from songbird import SongbirdCore, ProcessMode, ReliableMode


def test_string_serialization():
    """Test string write and read operations."""
    print("\n=== String Serialization Test ===")
    
    # Create a test core (not connected to anything)
    core = SongbirdCore("test", ProcessMode.PACKET, ReliableMode.UNRELIABLE)
    
    # Create a packet and write strings
    pkt = core.create_packet(0x10)
    pkt.write_string("Hello, World!")
    pkt.write_string("")  # Empty string
    pkt.write_string("Test message with special chars: ñ, ü, 中文")
    
    # Simulate serialization and deserialization
    data = pkt.to_bytes(ProcessMode.PACKET, ReliableMode.UNRELIABLE)
    print(f"Serialized packet size: {len(data)} bytes")
    
    # Read back the strings
    result1 = pkt.read_string()
    result2 = pkt.read_string()
    result3 = pkt.read_string()
    
    # Reset read position to demonstrate reading again
    pkt.read_pos = 0
    
    # Read strings from the beginning
    str1 = pkt.read_string()
    str2 = pkt.read_string()
    str3 = pkt.read_string()
    
    print(f"String 1: '{str1}'")
    print(f"String 2: '{str2}'")
    print(f"String 3: '{str3}'")
    
    assert str1 == "Hello, World!", "First string mismatch"
    assert str2 == "", "Empty string mismatch"
    assert str3 == "Test message with special chars: ñ, ü, 中文", "Third string mismatch"
    
    print("✓ All string tests passed!")


def test_protobuf_serialization():
    """Test protobuf write and read operations."""
    print("\n=== Protobuf Serialization Test ===")
    
    # Create a test core
    core = SongbirdCore("test", ProcessMode.PACKET, ReliableMode.UNRELIABLE)
    
    # Create a packet and write protobuf data
    # (In real use, you would serialize a protobuf message to bytes)
    pkt = core.create_packet(0x20)
    
    # Simulate protobuf data (just raw bytes for demonstration)
    proto_data1 = b'\x08\x96\x01\x12\x04test'
    proto_data2 = b'\x01\x02\x03'
    proto_data3 = b''  # Empty protobuf
    
    pkt.write_protobuf(proto_data1)
    pkt.write_protobuf(proto_data2)
    pkt.write_protobuf(proto_data3)
    
    # Simulate serialization
    data = pkt.to_bytes(ProcessMode.PACKET, ReliableMode.UNRELIABLE)
    print(f"Serialized packet size: {len(data)} bytes")
    
    # Reset read position to read from beginning
    pkt.read_pos = 0
    
    # Read protobuf data back
    result1 = pkt.read_protobuf()
    result2 = pkt.read_protobuf()
    result3 = pkt.read_protobuf()
    
    print(f"Protobuf 1 size: {len(result1)} bytes")
    print(f"Protobuf 2 size: {len(result2)} bytes")
    print(f"Protobuf 3 size: {len(result3)} bytes")
    
    assert result1 == proto_data1, "First protobuf data mismatch"
    assert result2 == proto_data2, "Second protobuf data mismatch"
    assert result3 == proto_data3, "Empty protobuf data mismatch"
    
    print("✓ All protobuf tests passed!")


def test_mixed_serialization():
    """Test mixing different data types in a packet."""
    print("\n=== Mixed Serialization Test ===")
    
    core = SongbirdCore("test", ProcessMode.PACKET, ReliableMode.UNRELIABLE)
    
    # Create a packet with mixed data types
    pkt = core.create_packet(0x30)
    pkt.write_byte(0x42)
    pkt.write_int16(12345)
    pkt.write_string("sensor_data")
    pkt.write_float(3.14159)
    pkt.write_protobuf(b'\x08\x01\x10\x02')
    pkt.write_string("end_marker")
    
    # Reset and read back
    pkt.read_pos = 0
    
    byte_val = pkt.read_byte()
    int_val = pkt.read_int16()
    str_val = pkt.read_string()
    float_val = pkt.read_float()
    proto_val = pkt.read_protobuf()
    end_str = pkt.read_string()
    
    print(f"Byte: 0x{byte_val:02X}")
    print(f"Int16: {int_val}")
    print(f"String: '{str_val}'")
    print(f"Float: {float_val:.5f}")
    print(f"Protobuf size: {len(proto_val)} bytes")
    print(f"End marker: '{end_str}'")
    
    assert byte_val == 0x42, "Byte value mismatch"
    assert int_val == 12345, "Int16 value mismatch"
    assert str_val == "sensor_data", "String value mismatch"
    assert abs(float_val - 3.14159) < 0.0001, "Float value mismatch"
    assert proto_val == b'\x08\x01\x10\x02', "Protobuf data mismatch"
    assert end_str == "end_marker", "End marker mismatch"
    
    print("✓ All mixed serialization tests passed!")


def main():
    """Run all serialization tests."""
    print("Songbird Serialization Examples")
    print("=" * 50)
    
    try:
        test_string_serialization()
        test_protobuf_serialization()
        test_mixed_serialization()
        
        print("\n" + "=" * 50)
        print("✓ All tests completed successfully!")
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
