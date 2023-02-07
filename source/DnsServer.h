#include <boost/asio.hpp>
#include "DnsPacket.h"
using namespace boost::asio;

namespace Dns
{
    class DnsServer
    {
    public:
        explicit DnsServer();

        void start_server(uint16_t port);

        void handle_incoming_request(const boost::system::error_code& ec,
                                     size_t bytes_read,
                                     std::array<uint8_t, DNS_BUF_SIZE> buf);

        void lookup(std::array<uint8_t, DNS_BUF_SIZE> buf);

        void handle_lookup(const boost::system::error_code& ec,
                           size_t bytes_read);

        void handle_server_response(const boost::system::error_code& ec,
                                    size_t bytes_read,
                                    std::array<uint8_t, DNS_BUF_SIZE> buf);
    private:
        io_context io;
        ip::udp::socket client_socket;
        ip::udp::socket lookup_socket;
        ip::udp::endpoint client;

    };
}

