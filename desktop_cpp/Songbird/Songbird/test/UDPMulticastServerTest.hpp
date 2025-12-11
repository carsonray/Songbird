// UDP client test (counterpart to the Arduino test runner)
// Mirrors UARTMasterTest but uses SongbirdUDP instead of SongbirdUART.
// Usage: UDPClientTest (the test will send to localhost:12345 by default)

#ifdef BUILD_UDP_MULTICAST_SERVER_TEST

#include <iostream>
#include <memory>
#include <string>
#include <chrono>
#include <thread>
#include <cmath>
#include <cstdio>

#include <boost/asio.hpp>

#include "../src/SongbirdCore.h"
#include "../src/SongbirdUDP.h"

#define UDP_MULTICAST_IP "239.255.0.1"
#define UDP_MULTICAST_PORT 1234

SongbirdUDP udp("UDP Node");
// UDP server protocol object
std::shared_ptr<SongbirdCore> core;

bool ledState = false;

int main() {
    // Gets data protocol
    core = udp.getProtocol();

    // Sets handler for identification messages
    core->setHeaderHandler(0x2, [&](std::shared_ptr<SongbirdCore::Packet> pkt) {
		std::string remoteIP = pkt->getRemoteIP().to_string();
		std::cout << "New multicast member at IP address "
            << remoteIP << "\n";
        });

    // Begins multicast connection
    if (!udp.listenMulticast(boost::asio::ip::make_address(UDP_MULTICAST_IP), UDP_MULTICAST_PORT)) {
        return 1;
    }

    // Sets multicast remote
	udp.setRemote(boost::asio::ip::make_address(UDP_MULTICAST_IP), UDP_MULTICAST_PORT);

	// Sends initial identification message
	auto idPkt = core->createPacket(0x1);
	core->sendPacket(idPkt);

	// Runs server loop to send LED toggle messages every second
    while (true) {
        // Sends LED toggle message
        auto pkt = core->createPacket(0x03);
        pkt.writeByte(ledState); // LED toggle
        core->sendPacket(pkt);
		std::cout << "Sent LED toggle: " << (ledState ? "ON" : "OFF") << "\n";
        ledState = !ledState;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
	return 0;
}

#endif // BUILD_UDP_TEST
