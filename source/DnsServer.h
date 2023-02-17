#include <boost/asio.hpp>
#include "DnsPacket.h"
using namespace boost::asio;

namespace Dns
{
    constexpr std::array<std::string_view, 13> root_server_strs {
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33",
    };

    static const std::array<ip::udp::endpoint , 13> root_server_eps{};

    static std::array<ip::udp::endpoint, 13> generate_root_server_eps {
        std::vector<ip::udp::endpoint> result;
    };

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
    struct NsLookup{};
    struct ClientLookup{};

    struct lookupStateVisitorForStart{
        void operator()(ClientLookup& /**/) const;
        void operator()(NsLookup& /**/) const;

        LookupHandler* handler;
    };

    struct lookupStateVisitorForHandlingServerResponse{
        void operator()(ClientLookup& /**/) const;
        void operator()(NsLookup& /**/) const;

        LookupHandler* handler;
        std::size_t response_size;
    };

    private:
        std::stack<ip::udp::endpoint> lookup_servers;
        std::variant<NsLookup,ClientLookup> lookupState;
        ip::udp::socket& lookup_socket_;   //ref is okay server always lives longer
        ip::udp::socket& client_socket_;   //ref is okay server always lives longer
        ip::udp::endpoint client_;   // copy
        std::array<uint8_t, DNS_BUF_SIZE> original_req_buf_; //copy with memcpy
        std::size_t original_req_buf_size_;
        std::array<uint8_t, DNS_BUF_SIZE> buf_; // for lookups
        std::size_t buf_size_;
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

