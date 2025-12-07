#define BUILD_UDP_TEST

#if defined(BUILD_UART_TEST)
#include "../test/UARTMasterTest.hpp"
#elif defined(BUILD_UDP_TEST)
#include "../test/UDPClientTest.hpp"
#else
#error "No test selected (define BUILD_UART_TEST or BUILD_UDP_TEST)"
#endif