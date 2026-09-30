#ifndef ISTREAM_H
#define ISTREAM_H

#include <boost/asio.hpp>
#include <string>

class IStream {
public:
    class Endpoint {
    public:
        virtual bool operator==(const Endpoint& other);

        virtual bool operator!=(const Endpoint& other);

        virtual Endpoint getDefault();

        virtual std::string toString();
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