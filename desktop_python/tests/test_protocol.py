import math
import time

from songbird import IStream, ProcessMode, ReliableMode, SongbirdCore

MODE = ProcessMode.PACKET
RELIABILITY = ReliableMode.UNRELIABLE


class MockStream(IStream):
    def __init__(self, name):
        self.protocol = SongbirdCore(name, MODE, RELIABILITY)
        self.protocol.attach_stream(self)
        self.protocol.set_missing_packet_timeout(10)
        self.protocol.set_retransmission_timeout(200)
        self.peer = None
        self.open = True
        self.blocked = False
        self.incoming = bytearray()

    def set_peer(self, peer):
        self.peer = peer

    def write(self, buffer: bytes) -> None:
        if self.peer is None:
            return
        if self.peer.blocked:
            return
        self.peer.incoming.extend(buffer)

    def is_open(self) -> bool:
        return self.open

    def close(self) -> None:
        self.open = False

    def supports_remote_write(self) -> bool:
        return False

    def update_data(self) -> None:
        if not self.incoming:
            return
        self.protocol.parse_data(bytes(self.incoming))
        self.incoming.clear()


class StreamMockStream(IStream):
    def __init__(self, name):
        self.protocol = SongbirdCore(name, ProcessMode.STREAM, RELIABILITY)
        self.protocol.attach_stream(self)
        self.protocol.set_missing_packet_timeout(10)
        self.peer = None
        self.open = True
        self.incoming = bytearray()

    def set_peer(self, peer):
        self.peer = peer

    def write(self, buffer: bytes) -> None:
        if self.peer is None:
            return
        self.peer.incoming.extend(buffer)

    def is_open(self) -> bool:
        return self.open

    def close(self) -> None:
        self.open = False

    def supports_remote_write(self) -> bool:
        return False

    def update_data(self) -> None:
        if not self.incoming:
            return
        self.protocol.parse_data(bytes(self.incoming))
        self.incoming.clear()


def make_linked_cores():
    stream_a = MockStream("A")
    stream_b = MockStream("B")
    stream_a.set_peer(stream_b)
    stream_b.set_peer(stream_a)
    return stream_a, stream_b, stream_a.protocol, stream_b.protocol


def test_basic_send_receive():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    received = {"packet": None}
    core_b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    pkt = core_a.create_packet(0x10)
    pkt.write_byte(0x42)
    core_a.send_packet(pkt)

    stream_b.update_data()

    assert received["packet"] is not None
    assert received["packet"].get_header() == 0x10
    assert received["packet"].get_payload_length() == 1
    assert received["packet"].read_byte() == 0x42


def test_specific_handler():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    header = 0x10
    received = {"packet": None}
    calls = []

    def header_handler(pkt):
        calls.append(pkt.get_header())
        received["packet"] = pkt

    core_b.set_header_handler(header, header_handler)

    pkt = core_a.create_packet(header)
    pkt.write_byte(0x42)
    core_a.send_packet(pkt)
    stream_b.update_data()

    assert received["packet"] is not None
    assert received["packet"].get_header() == 0x10
    assert received["packet"].get_payload_length() == 1
    assert received["packet"].read_byte() == 0x42

    pkt2 = core_a.create_packet(0x20)
    pkt2.write_byte(0x99)
    core_a.send_packet(pkt2)
    stream_b.update_data()

    assert calls == [0x10]


def test_request_response():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    REQ = 0x01
    RESP = 0x02

    def read_handler(pkt):
        if pkt.get_header() == REQ:
            response = core_b.create_packet(RESP)
            response.write_byte(0x99)
            core_b.send_packet(response)

    core_b.set_read_handler(read_handler)

    req = core_a.create_packet(REQ)
    core_a.send_packet(req)

    stream_b.update_data()
    stream_a.update_data()

    resp = core_a.wait_for_header(RESP, 1000)
    assert resp is not None
    assert resp.get_header() == RESP
    assert resp.read_byte() == 0x99

    resp2 = core_a.wait_for_header(0xFF, 100)
    assert resp2 is None


def test_integer_payload():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    received = {"packet": None}
    core_b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    pkt = core_a.create_packet(0x30)
    value = -12345
    pkt.write_int16(value)
    core_a.send_packet(pkt)
    stream_b.update_data()

    assert received["packet"] is not None
    assert received["packet"].read_int16() == value


def test_float_payload():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    received = {"packet": None}
    core_b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    pkt = core_a.create_packet(0x31)
    value = 3.14159
    pkt.write_float(value)
    core_a.send_packet(pkt)
    stream_b.update_data()

    assert received["packet"] is not None
    assert math.isclose(received["packet"].read_float(), value, rel_tol=0.0, abs_tol=0.0001)


def test_guaranteed_delivery_with_retransmit():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    receive_count = {"count": 0}
    received = {"packet": None}

    def read_handler(pkt):
        receive_count["count"] += 1
        received["packet"] = pkt

    core_b.set_read_handler(read_handler)
    stream_b.blocked = True

    pkt = core_a.create_packet(0x50)
    pkt.write_byte(0xAA)
    core_a.send_packet(pkt, guarantee_delivery=True)

    stream_b.update_data()
    assert receive_count["count"] == 0

    time.sleep(0.06)
    seq_num = pkt.get_sequence_num()
    core_a._on_retransmission_timeout(seq_num)
    stream_b.update_data()
    assert receive_count["count"] == 0

    stream_b.blocked = False
    time.sleep(0.25)
    core_a._on_retransmission_timeout(seq_num)
    stream_b.update_data()

    assert receive_count["count"] == 1
    assert received["packet"] is not None
    assert received["packet"].get_header() == 0x50
    assert received["packet"].read_byte() == 0xAA

    stream_a.update_data()
    time.sleep(0.08)
    core_a._on_retransmission_timeout(seq_num)
    stream_b.update_data()
    assert receive_count["count"] == 1


def test_repeat_blocking():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    receive_count = {"count": 0}
    received = {"packet": None}

    def read_handler(pkt):
        receive_count["count"] += 1
        received["packet"] = pkt

    core_b.set_read_handler(read_handler)

    pkt1 = core_a.create_packet(0x60)
    pkt1.write_byte(0xBB)
    core_a.send_packet(pkt1)
    stream_b.update_data()

    assert receive_count["count"] == 1
    assert received["packet"].read_byte() == 0xBB

    pkt2 = core_a.create_packet(0x61)
    pkt2.write_byte(0xCC)
    core_a.send_packet(pkt2, guarantee_delivery=True)
    stream_b.update_data()

    assert receive_count["count"] == 2
    assert received["packet"].read_byte() == 0xCC

    stream_a.update_data()

    pkt3 = core_a.create_packet(0x62)
    pkt3.write_byte(0xDD)
    core_a.send_packet(pkt3, seq_num=255, guarantee_delivery=True)
    stream_b.update_data()

    assert receive_count["count"] == 2


def test_string_serialization():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    received = {"packet": None}
    core_b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    pkt = core_a.create_packet(0x80)
    pkt.write_string("Hello, World!")
    pkt.write_string("")
    pkt.write_string("Test")
    core_a.send_packet(pkt)
    stream_b.update_data()

    assert received["packet"] is not None
    assert received["packet"].read_string() == "Hello, World!"
    assert received["packet"].read_string() == ""
    assert received["packet"].read_string() == "Test"


def test_protobuf_serialization():
    stream_a, stream_b, core_a, core_b = make_linked_cores()
    received = {"packet": None}
    core_b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    proto_data_1 = [0x08, 0x96, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74]
    proto_data_2 = [0x01, 0x02, 0x03]

    pkt = core_a.create_packet(0x81)
    pkt.write_protobuf(bytes(proto_data_1))
    pkt.write_protobuf(bytes(proto_data_2))
    core_a.send_packet(pkt)
    stream_b.update_data()

    assert received["packet"] is not None
    result1 = received["packet"].read_protobuf()
    assert len(result1) == len(proto_data_1)
    assert list(result1) == proto_data_1

    result2 = received["packet"].read_protobuf()
    assert len(result2) == len(proto_data_2)
    assert list(result2) == proto_data_2


def test_stream_mode_basic():
    s1 = StreamMockStream("A")
    s2 = StreamMockStream("B")
    s1.set_peer(s2)
    s2.set_peer(s1)

    a = s1.protocol
    b = s2.protocol
    received = {"packet": None}
    b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    pkt = a.create_packet(0x70)
    pkt.write_byte(0xAB)
    pkt.write_byte(0xCD)
    a.send_packet(pkt)

    s2.update_data()

    assert received["packet"] is not None
    assert received["packet"].get_header() == 0x70
    assert received["packet"].get_payload_length() == 2
    assert received["packet"].read_byte() == 0xAB
    assert received["packet"].read_byte() == 0xCD


def test_stream_mode_multiple_packets():
    s1 = StreamMockStream("A")
    s2 = StreamMockStream("B")
    s1.set_peer(s2)
    s2.set_peer(s1)

    a = s1.protocol
    b = s2.protocol
    received = []
    b.set_read_handler(lambda pkt: received.append(pkt))

    for i in range(3):
        pkt = a.create_packet(0x71 + i)
        pkt.write_byte(0x10 + i)
        a.send_packet(pkt)

    s2.update_data()

    assert len(received) == 3
    for i, pkt in enumerate(received):
        assert pkt.get_header() == 0x71 + i
        assert pkt.read_byte() == 0x10 + i


def test_stream_mode_zero_bytes_in_payload():
    s1 = StreamMockStream("A")
    s2 = StreamMockStream("B")
    s1.set_peer(s2)
    s2.set_peer(s1)

    a = s1.protocol
    b = s2.protocol
    received = {"packet": None}
    b.set_read_handler(lambda pkt: received.__setitem__("packet", pkt))

    pkt = a.create_packet(0x75)
    pkt.write_byte(0x00)
    pkt.write_byte(0x01)
    pkt.write_byte(0x00)
    pkt.write_byte(0x02)
    a.send_packet(pkt)

    s2.update_data()

    assert received["packet"] is not None
    assert received["packet"].get_header() == 0x75
    assert received["packet"].get_payload_length() == 4
    assert received["packet"].read_byte() == 0x00
    assert received["packet"].read_byte() == 0x01
    assert received["packet"].read_byte() == 0x00
    assert received["packet"].read_byte() == 0x02
