#ifndef ISTREAM_H
#define ISTREAM_H

#include <boost/asio.hpp>

class IStream {
public:
    class Endpoint {
    public:
        boost::asio::ip::address ip;
        uint16_t port = 0;

        bool operator==(const Endpoint& other) const {
            return ip == other.ip && port == other.port;
        }

        bool operator!=(const Endpoint& other) const {
            return !(*this == other);
        }

        Endpoint getDefault() const {
            return *this;
        }
    };

    virtual ~IStream() = default;

    virtual void write(const uint8_t* buffer, std::size_t length) = 0;
    virtual bool isOpen() const = 0;
    virtual void close() = 0;

    virtual Endpoint getEndpoint() const {
        return Endpoint{};
    }

    virtual void write(const uint8_t* buffer, std::size_t length, const Endpoint&) {
        write(buffer, length);
    }
};

#endif // ISTREAM_H