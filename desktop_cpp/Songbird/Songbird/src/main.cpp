#define BUILD_UART_TEST

#if defined(BUILD_UART_TEST)
#include "../test/UARTMasterTest.hpp"
#elif defined(BUILD_UDP_CLIENT_TEST)
#include "../test/UDPClientTest.hpp"
#elif defined(BUILD_UDP_MULTICAST_SERVER_TEST)
#include "../test/UDPMulticastServerTest.hpp"
#else
#error "No test selected"
#endif