#include <boost/asio.hpp>
#include "DnsPacket.h"
using namespace boost::asio;

namespace Dns
{
    class DnsServer
    {
    public:
        explicit DnsServer(int thread_count =1);

        void start_server(uint16_t port);

        void handle_incoming_request(const boost::system::error_code& ec,
                                     size_t bytes_read,
                                     std::array<uint8_t, DNS_BUF_SIZE> buf);
    private:
        int thread_count;
        std::vector<std::thread> thread_pool;
        io_context io;
        ip::udp::socket socket;

    };
}

