#ifndef ISTREAM_H
#define ISTREAM_H

#include <Arduino.h>
#include <utility>

class IStream {
    public:
        class Endpoint {
        public:
            Endpoint() = default;
            explicit Endpoint(std::string value) : value(std::move(value)) {}

            bool operator==(const Endpoint& other) const {
                return value == other.value;
            }

            bool operator!=(const Endpoint& other) const {
                return !(*this == other);
            }

            std::string toString() const {
                return value;
            }

        private:
            std::string value;
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
