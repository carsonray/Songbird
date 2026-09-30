#ifndef ISTREAM_H
#define ISTREAM_H

#include <Arduino.h>

class IStream {
    public:
        class Endpoint {
        public:
            IPAddress ip;
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

        virtual void write(const uint8_t* buffer, std::size_t length);
        virtual bool isOpen() const;
        virtual void close();
        
        // Update/poll for new data (if applicable)
        virtual void updateData() {}
        
        virtual Endpoint getEndpoint() const {
            return Endpoint{};
        }

        virtual void write(const uint8_t* buffer, std::size_t length, const Endpoint&) {
            write(buffer, length);
        }
};

#endif // ISTREAM_H
