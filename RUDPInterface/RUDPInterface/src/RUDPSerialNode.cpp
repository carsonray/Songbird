#include "RUDPSerialNode.h"
#include <vector>

RUDPSerialNode::RUDPSerialNode(std::string name,
                               boost::asio::io_context& io_context,
                               const std::string& device)
    : io_context_(io_context), device_(device), protocol(std::make_shared<RUDPCore>(name)) {
    protocol->setMissingPacketTimeout(10);
}

RUDPSerialNode::~RUDPSerialNode() {
    end();
}

static void startAsyncReadLoop(std::shared_ptr<SerialStream> stream, std::shared_ptr<RUDPCore> protocol, std::atomic<bool>& active);

bool RUDPSerialNode::begin(unsigned int baudRate) {
    // create serial_port
    serialPort_ = std::make_shared<boost::asio::serial_port>(io_context_);
    boost::system::error_code ec;
    serialPort_->open(device_, ec);
    if (ec) return false;
    serialPort_->set_option(boost::asio::serial_port_base::baud_rate(static_cast<unsigned int>(baudRate)), ec);
    if (ec) {
        serialPort_->close();
        return false;
    }

    // construct async wrapper SerialStream which uses shared_ptr<serial_port>
    serialStream = std::make_shared<SerialStream>(serialPort_);

    // Attach the async serial stream to protocol so protocol can use it for writes
    protocol->attachStream(serialStream);

    // start io_context thread
    if (!ioThread_) {
        ioThread_ = std::make_unique<std::thread>([this]() {
            try {
                io_context_.run();
            } catch (...) {
            }
        });
    }

    // start async read loop to notify protocol when data arrives
    asyncActive.store(true);
    startAsyncReadLoop(serialStream, protocol, asyncActive);

    return true;
}

void RUDPSerialNode::updateDate() {
    protocol->updateData();
}

void RUDPSerialNode::end() {
    asyncActive.store(false);
    if (serialStream) serialStream->close();
    if (serialPort_ && serialPort_->is_open()) {
        boost::system::error_code ec;
        serialPort_->cancel(ec);
        serialPort_->close(ec);
    }
    io_context_.stop();
    if (ioThread_ && ioThread_->joinable()) {
        ioThread_->join();
        ioThread_.reset();
    }
}

std::shared_ptr<RUDPCore> RUDPSerialNode::getProtocol() {
    return protocol;
}

bool RUDPSerialNode::isOpen() const {
    return serialPort_ && serialPort_->is_open();
}

static const std::size_t ASYNC_READ_BUF = 512;

static void startAsyncReadLoop(std::shared_ptr<SerialStream> stream, std::shared_ptr<RUDPCore> protocol, std::atomic<bool>& active) {
    if (!stream || !active.load()) return;

    auto buf = std::make_shared<std::vector<uint8_t>>(ASYNC_READ_BUF);

    stream->asyncRead(buf->data(), buf->size(), [stream, protocol, buf, &active](const boost::system::error_code& ec, std::size_t bytesTransferred) {
        if (!active.load()) return;
        if (!ec && bytesTransferred > 0) {
            // Let the protocol pull data from the stream in its updateData call
            // The serialStream implementation should make the data available via its read()/available() if required.
            protocol->updateData();
        }

        // Reschedule next async read
        if (active.load()) {
            startAsyncReadLoop(stream, protocol, active);
        }
    });
}