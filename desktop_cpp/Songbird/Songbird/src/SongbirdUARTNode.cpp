#include "SongbirdUARTNode.h"
#include <vector>

SongbirdUARTNode::SongbirdUARTNode(std::string name)
    : serialStream(std::make_shared<UARTStream>(std::make_shared<boost::asio::serial_port>(ioContext))),
    protocol(std::make_shared<SongbirdCore>(name))
{
    protocol->setMissingPacketTimeout(10);
	protocol->setReliabilityEnabled(true);
}

SongbirdUARTNode::~SongbirdUARTNode() {
    end();
}

static void startAsyncReadLoop(std::shared_ptr<UARTStream> stream, std::shared_ptr<SongbirdCore> protocol, std::atomic<bool>& active);

bool SongbirdUARTNode::begin(const std::string& port, unsigned int baudRate) {
    try {
        auto serialPort = serialStream->getSerialPort();
        serialPort->open(port);
        serialPort->set_option(boost::asio::serial_port_base::baud_rate(baudRate));
        serialPort->set_option(boost::asio::serial_port_base::character_size(8));
        serialPort->set_option(boost::asio::serial_port_base::parity(boost::asio::serial_port_base::parity::none));
        serialPort->set_option(boost::asio::serial_port_base::stop_bits(boost::asio::serial_port_base::stop_bits::one));
        serialPort->set_option(boost::asio::serial_port_base::flow_control(boost::asio::serial_port_base::flow_control::none));

        // Attach the async serial stream to protocol so protocol can use it for writes
        protocol->attachStream(serialStream);

        // Start io thread
        ioThread = std::thread([this]() { ioContext.run(); });

        // start async read loop to notify protocol when data arrives
        asyncActive.store(true);
        startAsyncReadLoop(serialStream, protocol, asyncActive);
        return true;
    }
    catch (boost::system::system_error& e) {
        std::cerr << "Error opening serial port: " << e.what() << std::endl;
        return false;
    }
}

void SongbirdUARTNode::end() {
    asyncActive.store(false);
    if (serialStream && serialStream->isOpen()) {
        serialStream->close();
    }

    ioContext.stop();
    if (ioThread.joinable()) {
        ioThread.join();
    }
}

std::shared_ptr<SongbirdCore> SongbirdUARTNode::getProtocol() {
    return protocol;
}

bool SongbirdUARTNode::isOpen() const {
    return serialStream && serialStream->isOpen();
}

static const std::size_t ASYNC_READ_BUF = 512;

static void startAsyncReadLoop(std::shared_ptr<UARTStream> stream, std::shared_ptr<SongbirdCore> protocol, std::atomic<bool>& active) {
    if (!stream || !active.load()) return;

    auto buf = std::make_shared<std::vector<uint8_t>>(ASYNC_READ_BUF);

    stream->asyncRead(buf->data(), buf->size(), [stream, protocol, buf, &active](const boost::system::error_code& ec, std::size_t bytesTransferred) {
        if (!active.load()) return;
        if (!ec && bytesTransferred > 0) {
            // Append received data to protocol read buffer
            protocol->appendToReadBuffer(buf->data(), bytesTransferred);

            // Let the protocol pull data in its updateData call
            protocol->updateData();
        }

        // Reschedule next async read
        if (active.load()) {
            startAsyncReadLoop(stream, protocol, active);
        }
    });
}