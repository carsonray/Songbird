"""
SongbirdCore Protocol Implementation

Core protocol handling for the Songbird communication system.
Supports both STREAM and PACKET modes with RELIABLE and UNRELIABLE delivery.
"""

import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, IntFlag
from typing import Optional, Callable, Dict, List, Tuple
from collections import deque
import logging
from cobs import cobs
from .istream import IStream


class ProcessMode(Enum):
    """Processing mode for the protocol."""
    STREAM = "stream"
    PACKET = "packet"


class ReliableMode(Enum):
    """Reliability mode for packet delivery."""
    UNRELIABLE = "unreliable"
    RELIABLE = "reliable"


ACK_HEADER = 0x00
NACK_CODE = 0x01


class LogEvent(IntFlag):
    DROPPED = 1 << 0
    RETRANSMITTED = 1 << 1
    SENT = 1 << 2
    RECEIVED = 1 << 3
    RATE = 1 << 4


@dataclass
class Logging:
    events: LogEvent = LogEvent(0)
    endpoint: Optional[IStream.Endpoint] = None
    header: Optional[int] = None
    rate_interval_ms: int = 1000


@dataclass
class EndpointOrder:
    """Tracks the most recent sequence number seen from an endpoint."""
    expected_seq_num: int = 0
    missing_timer_active: bool = False
    missing_timer_start: float = 0.0


@dataclass
class OutgoingInfo:
    """Tracks outgoing guaranteed packets."""
    packet: 'Packet' = None
    endpoint: IStream.Endpoint = field(default_factory=IStream.Endpoint)
    send_time: float = 0.0
    retransmit_count: int = 0


class Packet:
    """Represents a protocol packet."""

    def __init__(self, header: int, payload: bytes = b""):
        """
        Create a packet.
        
        Args:
            header: Packet header byte
            payload: Optional payload bytes
        """
        self.header = header
        self.sequence_num = 0
        self.guaranteed_flag = False
        self.checksum_valid = True
        self.payload = bytearray(payload)
        self.read_pos = 0
        self.endpoint = IStream.Endpoint()

    def to_bytes(self, mode: ProcessMode, reliable_mode: ReliableMode) -> bytes:
        """
        Convert packet to bytes for transmission.
        
        Args:
            mode: Processing mode (STREAM or PACKET)
            reliable_mode: Reliability mode (RELIABLE or UNRELIABLE)
            
        Returns:
            Packet as bytes (COBS encoded with 0x00 delimiter in STREAM mode)
        """
        out = bytearray()

        if reliable_mode == ReliableMode.RELIABLE:
            # RELIABLE mode: no seq/guaranteed bytes
            # STREAM: [header][payload] (COBS encoded)
            # PACKET: [header][payload]
            out.append(self.header)
        else:
            # UNRELIABLE mode: includes seq/guaranteed bytes
            # STREAM: [header][seq][guaranteed][payload][checksum] (COBS encoded)
            # PACKET: [header][seq][guaranteed][payload][checksum]
            out.append(self.header)
            out.append(self.sequence_num & 0xFF)
            out.append(1 if self.guaranteed_flag else 0)

        out.extend(self.payload)

        if reliable_mode == ReliableMode.UNRELIABLE:
            checksum = 0
            for byte in out:
                checksum ^= byte
            out.append(checksum)
        
        # Apply COBS encoding in STREAM mode
        if mode == ProcessMode.STREAM:
            encoded = cobs.encode(bytes(out))
            return encoded + b'\x00'  # Add delimiter
        else:
            return bytes(out)

    def set_sequence_num(self, seq_num: int) -> None:
        """Set the sequence number."""
        self.sequence_num = seq_num & 0xFF

    def set_guaranteed(self, guaranteed: bool = True) -> None:
        """Set the guaranteed delivery flag."""
        self.guaranteed_flag = guaranteed

    def is_guaranteed(self) -> bool:
        """Check if guaranteed delivery is enabled."""
        return self.guaranteed_flag

    def is_checksum_valid(self) -> bool:
        """Return whether the received unreliable-frame checksum was valid."""
        return self.checksum_valid

    def get_header(self) -> int:
        """Get the packet header."""
        return self.header

    def get_sequence_num(self) -> int:
        """Get the sequence number."""
        return self.sequence_num

    def get_payload(self) -> bytes:
        """Get the payload as bytes."""
        return bytes(self.payload)

    def get_payload_length(self) -> int:
        """Get the payload length."""
        return len(self.payload)

    def get_remaining_bytes(self) -> int:
        """Get the number of unread bytes in the payload."""
        return len(self.payload) - self.read_pos

    def set_endpoint(self, endpoint: IStream.Endpoint) -> None:
        """Set the endpoint."""
        self.endpoint = endpoint

    def get_endpoint(self) -> IStream.Endpoint:
        """Get the endpoint."""
        return self.endpoint

    # Writing functions
    def write_bytes(self, buffer: bytes) -> None:
        """Write bytes to the payload."""
        self.payload.extend(buffer)

    def write_byte(self, value: int) -> None:
        """Write a single byte to the payload."""
        self.payload.append(value & 0xFF)

    def write_int16(self, value: int) -> None:
        """Write a 16-bit integer to the payload (big-endian)."""
        self.payload.extend(struct.pack('>h', value))

    def write_float(self, value: float) -> None:
        """Write a 32-bit float to the payload (big-endian)."""
        self.payload.extend(struct.pack('>f', value))

    def write_string(self, value: str) -> None:
        """Write a string with length prefix (uint16_t length + UTF-8 bytes)."""
        encoded = value.encode('utf-8')
        length = len(encoded)
        # Write length as uint16_t (big-endian)
        self.payload.extend(struct.pack('>H', length))
        # Write string bytes
        self.payload.extend(encoded)

    def write_protobuf(self, data: bytes) -> None:
        """Write a length-prefixed byte array (for protobuf messages)."""
        length = len(data)
        # Write length as uint16_t (big-endian)
        self.payload.extend(struct.pack('>H', length))
        # Write protobuf bytes
        self.payload.extend(data)

    # Reading functions
    def read_byte(self) -> int:
        """Read a single byte from the payload."""
        if self.read_pos >= len(self.payload):
            return 0
        value = self.payload[self.read_pos]
        self.read_pos += 1
        return value

    def peek_byte(self) -> int:
        """Peek at the next byte without consuming it."""
        if self.read_pos >= len(self.payload):
            return 0
        return self.payload[self.read_pos]

    def read_bytes(self, length: int) -> bytes:
        """Read multiple bytes from the payload."""
        available = len(self.payload) - self.read_pos
        to_read = min(length, available)
        result = bytes(self.payload[self.read_pos:self.read_pos + to_read])
        self.read_pos += to_read
        # Pad with zeros if requested more than available
        if to_read < length:
            result += b'\x00' * (length - to_read)
        return result

    def read_float(self) -> float:
        """Read a 32-bit float from the payload (big-endian)."""
        data = self.read_bytes(4)
        return struct.unpack('>f', data)[0]

    def read_int16(self) -> int:
        """Read a 16-bit integer from the payload (big-endian)."""
        data = self.read_bytes(2)
        return struct.unpack('>h', data)[0]

    def read_string(self) -> str:
        """Read a length-prefixed string from the payload."""
        # Read length (uint16_t, big-endian)
        length_data = self.read_bytes(2)
        length = struct.unpack('>H', length_data)[0]
        
        # Read string bytes
        if length == 0:
            return ""
        
        string_data = self.read_bytes(length)
        return string_data.decode('utf-8', errors='replace')

    def read_protobuf(self) -> bytes:
        """Read a length-prefixed byte array (for protobuf messages)."""
        # Read length (uint16_t, big-endian)
        length_data = self.read_bytes(2)
        length = struct.unpack('>H', length_data)[0]
        
        # Read protobuf bytes
        if length == 0:
            return b""
        
        return self.read_bytes(length)


class SongbirdCore:
    """Core protocol handler for Songbird communication."""

    def __init__(self, name: str, mode: ProcessMode = ProcessMode.PACKET, 
                 reliable_mode: ReliableMode = ReliableMode.UNRELIABLE):
        """
        Initialize the protocol core.
        
        Args:
            name: Name identifier for this instance
            mode: Processing mode (STREAM or PACKET)
            reliable_mode: Reliability mode (RELIABLE or UNRELIABLE)
        """
        self.name = name
        self.process_mode = mode
        self.reliable_mode = reliable_mode
        self.stream: Optional[IStream] = None
        self.read_buffer = bytearray()
        
        # Packet mode specific
        self.next_seq_num = 0
        self.endpoint_orders: Dict[IStream.Endpoint, EndpointOrder] = {}
        self.outgoing_guaranteed: Dict[int, OutgoingInfo] = {}
        
        # Timeouts
        self.missing_packet_timeout_ms = 100
        self.retransmission_timeout_ms = 1000
        self.max_retransmit_attempts = 5
        self.last_data_time_ms = 0
        
        # Stream mode specific
        self.new_packet = True
        
        # Handlers
        self.read_handler: Optional[Callable[[Packet], None]] = None
        self.header_handlers: Dict[int, Callable[[Packet], None]] = {}
        self.endpoint_handlers: Dict[IStream.Endpoint, Callable[[Packet], None]] = {}
        
        # Wait maps
        self.header_map: Dict[int, Packet] = {}
        self.endpoint_map: Dict[IStream.Endpoint, Packet] = {}
        
        # Waiters
        self.header_waiters: Dict[int, List[threading.Event]] = {}
        self.endpoint_waiters: Dict[IStream.Endpoint, List[threading.Event]] = {}
        self.waiter_packets: Dict[threading.Event, Optional[Packet]] = {}

        self.logging = Logging()
        self.header_log_tracks: Dict[int, Dict[str, int]] = {}
        self.endpoint_log_tracks: Dict[IStream.Endpoint, Dict[str, int]] = {}
        self.log_rate_window_start = time.monotonic()
        
        # Thread safety
        self.data_lock = threading.RLock()
        self.wait_lock = threading.Lock()

    def __del__(self):
        """Cleanup on deletion."""
        pass

    def attach_stream(self, stream: IStream) -> None:
        """Attach a stream for communication."""
        self.stream = stream

    def set_logging(self, logging_config: Logging) -> None:
        """Configure packet event and packets-per-second logging."""
        with self.data_lock:
            self.logging = logging_config
            self.header_log_tracks.clear()
            self.endpoint_log_tracks.clear()
            self.log_rate_window_start = time.monotonic()

    def _logging_matches(self, endpoint: IStream.Endpoint, header: int) -> bool:
        return ((self.logging.endpoint is None or self.logging.endpoint == endpoint) and
                (self.logging.header is None or self.logging.header == header))

    @staticmethod
    def _endpoint_text(endpoint: IStream.Endpoint) -> str:
        return f"{endpoint.ip}:{endpoint.port}"

    def _log_packet(self, event: LogEvent, packet: Packet, reason: Optional[str] = None) -> None:
        should_log = False
        rate_enabled = False
        with self.data_lock:
            if not self._logging_matches(packet.get_endpoint(), packet.get_header()):
                return

            header_track = self.header_log_tracks.setdefault(
                packet.get_header(), {"sent": 0, "received": 0})
            endpoint_track = self.endpoint_log_tracks.setdefault(
                packet.get_endpoint(), {"sent": 0, "received": 0})
            if event == LogEvent.SENT:
                header_track["sent"] += 1
                endpoint_track["sent"] += 1
            elif event == LogEvent.RECEIVED:
                header_track["received"] += 1
                endpoint_track["received"] += 1

            should_log = bool(self.logging.events & event)
            if should_log:
                suffix = f" reason={reason}" if reason else ""
                logging.info(
                    "[%s] %s header=%d seq=%d guaranteed=%d payload=%d endpoint=%s%s",
                    self.name, event.name, packet.get_header(), packet.get_sequence_num(),
                    int(packet.is_guaranteed()), packet.get_payload_length(),
                    self._endpoint_text(packet.get_endpoint()), suffix)
            rate_enabled = bool(self.logging.events & LogEvent.RATE)

        if should_log or rate_enabled:
            self._log_rates_if_due()

    def _log_timeout(self, endpoint: IStream.Endpoint) -> None:
        with self.data_lock:
            if (not self.logging.events & LogEvent.DROPPED or
                    self.logging.endpoint is not None and self.logging.endpoint != endpoint or
                    self.logging.header is not None):
                return
            logging.info("[%s] DROPPED header=? seq=? guaranteed=? payload=? endpoint=%s reason=timeout",
                         self.name, self._endpoint_text(endpoint))

    def _log_rates_if_due(self) -> None:
        with self.data_lock:
            if not self.logging.events & LogEvent.RATE or self.logging.rate_interval_ms <= 0:
                return
            elapsed = time.monotonic() - self.log_rate_window_start
            if elapsed * 1000 < self.logging.rate_interval_ms:
                return
            for header, track in self.header_log_tracks.items():
                logging.info("[%s] RATE header=%d sent=%d received=%d pps=%.2f",
                             self.name, header, track["sent"], track["received"],
                             (track["sent"] + track["received"]) / elapsed)
            for endpoint, track in self.endpoint_log_tracks.items():
                logging.info("[%s] RATE endpoint=%s sent=%d received=%d pps=%.2f",
                             self.name, self._endpoint_text(endpoint), track["sent"],
                             track["received"], (track["sent"] + track["received"]) / elapsed)
            self.header_log_tracks.clear()
            self.endpoint_log_tracks.clear()
            self.log_rate_window_start = time.monotonic()

    def set_read_handler(self, handler: Callable[[Packet], None]) -> None:
        """Set global read handler for all packets."""
        with self.data_lock:
            self.read_handler = handler

    def set_header_handler(self, header: int, handler: Callable[[Packet], None]) -> None:
        """Set handler for packets with specific header."""
        if header == 0x00:
            logging.error("Header 0x00 is reserved for ACKs and cannot be used")
            return
        with self.data_lock:
            self.header_handlers[header] = handler

    def clear_header_handler(self, header: int) -> None:
        """Clear handler for specific header."""
        with self.data_lock:
            self.header_handlers.pop(header, None)
            self.header_map.pop(header, None)

    def set_endpoint_handler(self, endpoint: IStream.Endpoint,
                             handler: Callable[[Packet], None]) -> None:
        """Set handler for packets from a specific endpoint."""
        with self.data_lock:
            self.endpoint_handlers[endpoint] = handler

    def clear_endpoint_handler(self, endpoint: IStream.Endpoint) -> None:
        """Clear handler for a specific endpoint."""
        with self.data_lock:
            self.endpoint_handlers.pop(endpoint, None)
            self.endpoint_map.pop(endpoint, None)

    def wait_for_header(self, header: int, timeout_ms: int = 1000) -> Optional[Packet]:
        """
        Wait for a packet with specific header.
        
        Args:
            header: Header to wait for
            timeout_ms: Timeout in milliseconds
            
        Returns:
            Packet if received, None on timeout
        """
        # Check if already available
        with self.data_lock:
            if header in self.header_map:
                pkt = self.header_map.pop(header)
                return pkt
        
        # Register waiter
        event = threading.Event()
        with self.wait_lock:
            if header not in self.header_waiters:
                self.header_waiters[header] = []
            self.header_waiters[header].append(event)
            self.waiter_packets[event] = None
        
        # Wait for signal
        got = event.wait(timeout_ms / 1000.0)
        
        # Unregister waiter
        with self.wait_lock:
            if header in self.header_waiters:
                self.header_waiters[header].remove(event)
                if not self.header_waiters[header]:
                    del self.header_waiters[header]
            pkt = self.waiter_packets.pop(event, None)
        
        if not got:
            return None
        
        with self.data_lock:
            if header in self.header_map:
                return self.header_map.pop(header)
        return pkt

    def wait_for_endpoint(self, endpoint: IStream.Endpoint,
                          timeout_ms: int = 1000) -> Optional[Packet]:
        """
        Wait for a packet from a specific endpoint.
        
        Args:
            endpoint: Endpoint to wait for
            timeout_ms: Timeout in milliseconds
            
        Returns:
            Packet if received, None on timeout
        """
        # Check if already available
        with self.data_lock:
            if endpoint in self.endpoint_map:
                pkt = self.endpoint_map.pop(endpoint)
                return pkt
        
        # Register waiter
        event = threading.Event()
        with self.wait_lock:
            if endpoint not in self.endpoint_waiters:
                self.endpoint_waiters[endpoint] = []
            self.endpoint_waiters[endpoint].append(event)
            self.waiter_packets[event] = None
        
        # Wait for signal
        got = event.wait(timeout_ms / 1000.0)
        
        # Unregister waiter
        with self.wait_lock:
            if endpoint in self.endpoint_waiters:
                self.endpoint_waiters[endpoint].remove(event)
                if not self.endpoint_waiters[endpoint]:
                    del self.endpoint_waiters[endpoint]
            pkt = self.waiter_packets.pop(event, None)
        
        if not got:
            return None
        
        with self.data_lock:
            if endpoint in self.endpoint_map:
                return self.endpoint_map.pop(endpoint)
        return pkt

    def create_packet(self, header: int) -> Packet:
        """Create a new packet with the given header."""
        if header == 0x00:
            logging.error("Header 0x00 is reserved for ACKs and cannot be used")
            return Packet(0x01)
        return Packet(header)

    def set_missing_packet_timeout(self, ms: int) -> None:
        """Set missing packet timeout in milliseconds."""
        with self.data_lock:
            self.missing_packet_timeout_ms = ms

    def set_retransmission_timeout(self, ms: int) -> None:
        """Set retransmission timeout in milliseconds."""
        with self.data_lock:
            self.retransmission_timeout_ms = ms

    def set_max_retransmit_attempts(self, attempts: int) -> None:
        """Set maximum retransmit attempts."""
        with self.data_lock:
            self.max_retransmit_attempts = attempts

    def send_packet(self, packet: Packet, guarantee_delivery: bool = False, 
                   seq_num: Optional[int] = None) -> None:
        """
        Send a packet.
        
        Args:
            packet: Packet to send
            guarantee_delivery: Whether to guarantee delivery
            seq_num: Optional specific sequence number
        """
        if not self.stream or not self.stream.is_open():
            logging.error("Stream not attached or not open, cannot send packet")
            return
        
        # Assign sequence number
        if seq_num is None:
            seq_num = self.next_seq_num
            self.next_seq_num = (self.next_seq_num + 1) & 0xFF
        
        packet.set_sequence_num(seq_num)
        
        if guarantee_delivery:
            packet.set_guaranteed(True)
        
        # Convert to bytes and send
        data = packet.to_bytes(self.process_mode, self.reliable_mode)
        endpoint = packet.get_endpoint()
        if endpoint.port == 0:
            endpoint = self.stream.get_endpoint().get_default()
            packet.set_endpoint(endpoint)
        self.stream.write_to_endpoint(data, endpoint)
        self._log_packet(LogEvent.SENT, packet)
        
        # Track guaranteed packets
        if guarantee_delivery and self.reliable_mode == ReliableMode.UNRELIABLE:
            info = OutgoingInfo(
                packet=packet,
                endpoint=packet.get_endpoint(),
                send_time=time.time(),
                retransmit_count=0
            )
            
            with self.data_lock:
                self.outgoing_guaranteed[seq_num] = info

    def parse_data(self, data: bytes, endpoint: Optional[IStream.Endpoint] = None) -> None:
        """
        Parse incoming data.
        
        Args:
            data: Received data bytes
            endpoint: Source endpoint for packet mode
        """
        endpoint = endpoint or IStream.Endpoint()
        if self.process_mode == ProcessMode.PACKET:
            pkt = self._packet_from_data(data)
            if not pkt:
                return
            
            pkt.set_endpoint(endpoint)

            if not pkt.is_checksum_valid():
                self._log_packet(LogEvent.DROPPED, pkt, "checksum")
                if pkt.is_guaranteed():
                    nack_pkt = Packet(ACK_HEADER)
                    nack_pkt.set_endpoint(endpoint)
                    nack_pkt.write_byte(NACK_CODE)
                    self.send_packet(nack_pkt, guarantee_delivery=False,
                                     seq_num=pkt.get_sequence_num())
                return

            self._log_packet(LogEvent.RECEIVED, pkt)
            
            # Check for ACK
            if self._check_for_ack(pkt):
                return
            
            dispatch = [pkt]
            if self.reliable_mode == ReliableMode.UNRELIABLE and pkt.is_guaranteed():
                self._update_endpoint_order(pkt)
            
            for p in dispatch:
                self._call_handlers(p)
                
        elif self.process_mode == ProcessMode.STREAM:
            # Accumulate data and look for 0x00 delimiters (COBS packets)
            self._append_to_read_buffer(data)
            
            while True:
                pkt = self._packet_from_stream_cobs()
                if not pkt:
                    current_time_ms = time.time() * 1000
                    if current_time_ms - self.last_data_time_ms > self.missing_packet_timeout_ms:
                        self._log_timeout(endpoint)
                        self.flush()
                    break
                
                self.last_data_time_ms = time.time() * 1000
                pkt.set_endpoint(endpoint)

                if not pkt.is_checksum_valid():
                    self._log_packet(LogEvent.DROPPED, pkt, "checksum")
                    if pkt.is_guaranteed():
                        nack_pkt = Packet(ACK_HEADER)
                        nack_pkt.set_endpoint(endpoint)
                        nack_pkt.write_byte(NACK_CODE)
                        self.send_packet(nack_pkt, guarantee_delivery=False,
                                         seq_num=pkt.get_sequence_num())
                    continue

                self._log_packet(LogEvent.RECEIVED, pkt)
                
                if self._check_for_ack(pkt):
                    continue
                
                if self.reliable_mode == ReliableMode.UNRELIABLE:
                    self._update_endpoint_order(pkt)
                
                self._call_handlers(pkt)

    def _packet_from_data(self, data: bytes) -> Optional[Packet]:
        """Parse packet from raw data (packet mode)."""
        if self.reliable_mode == ReliableMode.RELIABLE:
            # RELIABLE: [header][payload]
            if len(data) < 1:
                return None
            header = data[0]
            payload = data[1:] if len(data) > 1 else b""
            return Packet(header, payload)
        else:
            # UNRELIABLE: [header][seq][guaranteed][payload][checksum]
            if len(data) < 3:
                return None
            header = data[0]
            seq_num = data[1]
            guaranteed = data[2]
            checksum = 0
            for byte in data[:-1]:
                checksum ^= byte
            checksum_valid = len(data) >= 4 and checksum == data[-1]
            payload = data[3:-1] if len(data) > 4 else b""
            
            pkt = Packet(header, payload)
            pkt.set_sequence_num(seq_num)
            if guaranteed:
                pkt.set_guaranteed()
            pkt.checksum_valid = checksum_valid
            return pkt

    def _packet_from_stream(self) -> Optional[Packet]:
        """Parse packet from stream buffer."""
        with self.data_lock:
            if self.reliable_mode == ReliableMode.RELIABLE:
                # RELIABLE: [header][length][payload]
                if self.new_packet:
                    if len(self.read_buffer) < 2:
                        return None
                    self.new_packet = False
                
                payload_len = self.read_buffer[1]
                if len(self.read_buffer) < 2 + payload_len:
                    return None
                
                self.new_packet = True
                header = self.read_buffer[0]
                payload = bytes(self.read_buffer[2:2 + payload_len])
                pkt = Packet(header, payload)
                del self.read_buffer[:2 + payload_len]
                return pkt
            else:
                # UNRELIABLE: [header][length][seq][guaranteed][payload][checksum]
                if self.new_packet:
                    if len(self.read_buffer) < 4:
                        return None
                    self.new_packet = False
                
                payload_len = self.read_buffer[1]
                if len(self.read_buffer) < 5 + payload_len:
                    return None
                
                self.new_packet = True
                header = self.read_buffer[0]
                seq_num = self.read_buffer[2]
                guaranteed = self.read_buffer[3]
                payload = bytes(self.read_buffer[4:4 + payload_len])
                received_checksum = self.read_buffer[4 + payload_len]
                checksum = 0
                for byte in self.read_buffer[:4 + payload_len]:
                    checksum ^= byte
                
                pkt = Packet(header, payload)
                pkt.set_sequence_num(seq_num)
                if guaranteed:
                    pkt.set_guaranteed()
                pkt.checksum_valid = checksum == received_checksum
                
                del self.read_buffer[:5 + payload_len]
                return pkt

    def _packet_from_stream_cobs(self) -> Optional[Packet]:
        """Parse COBS-encoded packet from stream buffer."""
        with self.data_lock:
            # Look for 0x00 delimiter
            try:
                delimiter_idx = self.read_buffer.index(0x00)
            except ValueError:
                # No complete packet yet
                return None
            
            # Extract and decode COBS packet
            if delimiter_idx == 0:
                # Empty packet, skip delimiter
                del self.read_buffer[0]
                return None
            
            cobs_data = bytes(self.read_buffer[:delimiter_idx])
            del self.read_buffer[:delimiter_idx + 1]  # Remove packet + delimiter
            
            try:
                decoded = cobs.decode(cobs_data)
            except cobs.DecodeError:
                logging.error("COBS decode error, skipping packet")
                return None
            
            if len(decoded) < 1:
                return None
            
            # Parse decoded packet
            if self.reliable_mode == ReliableMode.RELIABLE:
                # RELIABLE: [header][payload]
                header = decoded[0]
                payload = decoded[1:] if len(decoded) > 1 else b""
                return Packet(header, payload)
            else:
                # UNRELIABLE: [header][seq][guaranteed][payload][checksum]
                if len(decoded) < 3:
                    return None
                header = decoded[0]
                seq_num = decoded[1]
                guaranteed = decoded[2]
                checksum = 0
                for byte in decoded[:-1]:
                    checksum ^= byte
                checksum_valid = len(decoded) >= 4 and checksum == decoded[-1]
                payload = decoded[3:-1] if len(decoded) > 4 else b""
                
                pkt = Packet(header, payload)
                pkt.set_sequence_num(seq_num)
                if guaranteed:
                    pkt.set_guaranteed()
                pkt.checksum_valid = checksum_valid
                return pkt

    def _call_handlers(self, pkt: Packet) -> None:
        """Call registered handlers for a packet."""
        header = pkt.get_header()
        endpoint = pkt.get_endpoint()
        
        # Get handlers under lock
        with self.data_lock:
            header_handler = self.header_handlers.get(header)
            self.header_map[header] = pkt
            
            endpoint_handler = self.endpoint_handlers.get(endpoint)
            self.endpoint_map[endpoint] = pkt
            
            global_handler = self.read_handler
        
        # Notify waiters
        with self.wait_lock:
            if header in self.header_waiters and self.header_waiters[header]:
                event = self.header_waiters[header][0]
                self.waiter_packets[event] = pkt
                event.set()
            
            if endpoint in self.endpoint_waiters and self.endpoint_waiters[endpoint]:
                event = self.endpoint_waiters[endpoint][0]
                self.waiter_packets[event] = pkt
                event.set()
        
        # Call handlers outside lock
        if header_handler:
            header_handler(pkt)
        if endpoint_handler:
            endpoint_handler(pkt)
        if global_handler:
            global_handler(pkt)

    def _update_endpoint_order(self, pkt: Packet) -> None:
        """Track the last sequence number used to suppress exact duplicates."""
        with self.data_lock:
            now = time.monotonic()
            for endpoint, order in list(self.endpoint_orders.items()):
                if (order.missing_timer_active and
                        (now - order.missing_timer_start) * 1000 >= self.missing_packet_timeout_ms):
                    del self.endpoint_orders[endpoint]
                    self.endpoint_map.pop(endpoint, None)

            endpoint = pkt.get_endpoint()
            seq_num = pkt.get_sequence_num()
            self.endpoint_orders[endpoint] = EndpointOrder(
                expected_seq_num=seq_num,
                missing_timer_active=True,
                missing_timer_start=now,
            )

    def _is_repeat_packet(self, pkt: Packet) -> bool:
        """Check if this guaranteed packet is an older or duplicate sequence than the latest seen."""
        if not pkt.is_guaranteed():
            return False

        seq_num = pkt.get_sequence_num()
        endpoint = pkt.get_endpoint()

        with self.data_lock:
            if endpoint in self.endpoint_orders:
                expected_seq = self.endpoint_orders[endpoint].expected_seq_num
                # Treat any lower sequence number as a repeat relative to the last seen value.
                # This also handles unsigned wraparound correctly in 8-bit arithmetic.
                diff = (seq_num - expected_seq) & 0xFF
                if diff > 0x7F:
                    return True
            return False

    def _check_for_ack(self, pkt: Packet) -> bool:
        """Check and handle ACK packets."""
        if self.reliable_mode != ReliableMode.UNRELIABLE:
            return False
        
        # Check if this is an ACK or NACK packet
        if pkt.get_header() == ACK_HEADER:
            ack_seq = pkt.get_sequence_num()
            if pkt.get_payload_length() > 0 and pkt.get_payload()[0] == NACK_CODE:
                self._on_retransmission_timeout(ack_seq)
            else:
                self._remove_acknowledged_packet(ack_seq)
            return True
        
        # Send ACK if guaranteed
        if pkt.is_guaranteed():
            seq_num = pkt.get_sequence_num()
            endpoint = pkt.get_endpoint()
            
            ack_pkt = Packet(0x00)
            ack_pkt.set_endpoint(endpoint)
            self.send_packet(ack_pkt, guarantee_delivery=False, seq_num=seq_num)
        
        return self._is_repeat_packet(pkt)

    def _remove_acknowledged_packet(self, seq_num: int) -> None:
        """Remove acknowledged packet from retransmit queue."""
        with self.data_lock:
            self.outgoing_guaranteed.pop(seq_num, None)

    def _on_retransmission_timeout(self, seq_num: int) -> None:
        """Handle retransmission timeout."""
        need_resend = False
        info = None
        
        with self.data_lock:
            if seq_num in self.outgoing_guaranteed:
                info = self.outgoing_guaranteed[seq_num]
                
                if self.max_retransmit_attempts > 0 and info.retransmit_count >= self.max_retransmit_attempts:
                    del self.outgoing_guaranteed[seq_num]
                else:
                    need_resend = True
                    info.retransmit_count += 1
                    info.send_time = time.time()
        
        if need_resend and info:
            self._log_packet(LogEvent.RETRANSMITTED, info.packet)
            self.send_packet(info.packet, guarantee_delivery=False, seq_num=info.packet.get_sequence_num())

    def flush(self) -> None:
        """Flush all buffers."""
        with self.data_lock:
            self.read_buffer.clear()
            self.header_map.clear()
            self.new_packet = True

    def get_read_buffer_size(self) -> int:
        """Get read buffer size."""
        with self.data_lock:
            return len(self.read_buffer)

    def get_num_incoming_packets(self) -> int:
        """Buffered reordering is intentionally disabled; keep the API as a compatibility no-op."""
        return 0

    def _append_to_read_buffer(self, data: bytes) -> None:
        """Append data to read buffer."""
        with self.data_lock:
            self.read_buffer.extend(data)
