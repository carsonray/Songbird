#ifndef ISTREAM_H
#define ISTREAM_H

#include <Arduino.h>

class IStream {
    public:
        virtual ~IStream() = default;

        virtual void write(const uint8_t* buffer, std::size_t length);
        virtual bool isOpen() const;
        virtual void close();
        
        // Returns true if this stream supports dynamic remote addressing
        virtual bool supportsRemoteWrite() const { return false; }
        
        // Write to a specific remote (only supported if supportsRemoteWrite() returns true)
        virtual void writeToRemote(const uint8_t* buffer, std::size_t length, const IPAddress& ip, uint16_t port) {
            // Default implementation ignores remote and uses normal write
            write(buffer, length);
        }
        
        // Get the default remote for this stream (returns true if a default remote exists)
        virtual bool getDefaultRemote(IPAddress& outIP, uint16_t& outPort) { return false; }
};

#endif // ISTREAM_H
