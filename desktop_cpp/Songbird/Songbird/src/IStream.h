#ifndef ISTREAM_H
#define ISTREAM_H

#include <cstddef>
#include <stdint.h>

class IStream {
public:
    virtual ~IStream() = default;

    virtual void write(const uint8_t* buffer, std::size_t length) = 0;
    virtual bool isOpen() const = 0;
    virtual void close() = 0;
};

#endif // ISTREAM_H
