"""
IStream Interface

Abstract base class defining the interface for communication streams.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


class IStream(ABC):
    """Abstract interface for communication streams."""

    @dataclass(frozen=True)
    class Endpoint:
        """Address understood by a concrete stream."""
        ip: str = ""
        port: int = 0

        def get_default(self) -> "IStream.Endpoint":
            return self

    @abstractmethod
    def write(self, buffer: bytes) -> None:
        """
        Write data to the stream.
        
        Args:
            buffer: Bytes to write to the stream
        """
        pass

    @abstractmethod
    def is_open(self) -> bool:
        """
        Check if the stream is open.
        
        Returns:
            True if the stream is open, False otherwise
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the stream."""
        pass

    def get_endpoint(self) -> "IStream.Endpoint":
        return IStream.Endpoint()

    def write_to_endpoint(self, buffer: bytes, endpoint: "IStream.Endpoint") -> None:
        """Write to a stream-specific endpoint, or use normal stream output."""
        self.write(buffer)
