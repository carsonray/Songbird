#ifndef ISTREAM_H
#define ISTREAM_H

#include <boost/asio.hpp>

class IStream {
public:
    virtual ~IStream() = default;

    virtual void write(const uint8_t* buffer, std::size_t length) = 0;
    virtual bool isOpen() const = 0;
    virtual void close() = 0;

    // Returns true if this stream supports dynamic remote addressing
    virtual bool supportsRemoteWrite() const { return false; }

    // Write to a specific remote (only supported if supportsRemoteWrite() returns true)
    virtual void writeToRemote(const uint8_t* buffer, std::size_t length, const boost::asio::ip::address& ip, uint16_t port) {
        // Default implementation ignores remote and uses normal write
        write(buffer, length);
    }

    // Get the default remote for this stream (returns true if a default remote exists)
    virtual bool getDefaultRemote(boost::asio::ip::address& outIP, uint16_t& outPort) { return false; }
};

#endif // ISTREAM_H