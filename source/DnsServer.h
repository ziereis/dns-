#include <boost/asio.hpp>
#include "DnsPacket.h"
using namespace boost::asio;

namespace Dns
{
    class LookupHandler
            : public std::enable_shared_from_this<LookupHandler>
    {
    public:
        LookupHandler(std::span<const uint8_t> buf_view,ip::udp::socket& lookup_socket,
                      ip::udp::socket& client_socket, ip::udp::endpoint client);

        void start();

        void handle_lookup(const boost::system::error_code& ec,
                           size_t bytes_read);

        void handle_server_response(const boost::system::error_code& ec,
                                    size_t bytes_read);

    private:
        ip::udp::socket& lookup_socket_;   //ref is okay server always lives longer
        ip::udp::socket& client_socket_;   //ref is okay server always lives longer
        ip::udp::endpoint client_;   // copy
        ip::udp::endpoint server_;
        std::array<uint8_t, DNS_BUF_SIZE> original_req_buf_; //copy with memcpy
        std::array<uint8_t, DNS_BUF_SIZE> buf_; // for lookups
    };

    class DnsServer
    {
    public:
        explicit DnsServer();

        void start_server(uint16_t port);
    private:
        io_context ctx;
        ip::udp::socket client_socket;
        ip::udp::socket lookup_socket;
        std::array<uint8_t, DNS_BUF_SIZE> buf;
    };
}

