#ifndef ISTREAM_H
#define ISTREAM_H

#include <Arduino.h>

class IStream {
    public:
        virtual ~IStream() = default;

        virtual void write(const uint8_t* buffer, std::size_t length);
        virtual bool isOpen() const;
        virtual void close();
};

#endif // ISTREAM_H
