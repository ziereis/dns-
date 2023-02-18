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

    std::array<ip::udp::endpoint, 13> generate_root_server_eps(std::span<const std::string_view> ips);

    static const std::array<ip::udp::endpoint , 13> root_server_eps = generate_root_server_eps(root_server_strs);

    struct LookupTarget{
        ip::udp::endpoint ep_;   // copy
        std::deque<ip::udp::endpoint> available_endpoints_;
        std::array<uint8_t, DNS_BUF_SIZE> buf_;
        std::size_t buf_size_;
        ip::udp::socket& socket_;
    };

    struct InnerLookupTarget{
        std::deque<ip::udp::endpoint> available_endpoints_;
        std::span<uint8_t> buf_view_;
        ip::udp::socket& socket_;
    };

    struct LookupServer {
        ip::udp::endpoint& ep_;   // copy
        std::array<uint8_t, DNS_BUF_SIZE> buf_;
        //std::size_t buf_size_;
        ip::udp::socket& socket_;
    };

    class LookupHandler
            : public std::enable_shared_from_this<LookupHandler>
    {
    public:
        LookupHandler(std::span<const uint8_t> buf_view,ip::udp::socket& lookup_socket,
                      ip::udp::socket& client_socket, ip::udp::endpoint client_ep);

        void start();

        void handle_lookup(const boost::system::error_code& ec,
                           size_t bytes_sent);

        void handle_server_response(const boost::system::error_code& ec,
                                    size_t bytes_read);

        template<typename T>
        requires std::is_same_v<T, LookupTarget> || std::is_same_v<T, InnerLookupTarget>
        void handle_contains_additional(T& target, const DnsPacket&);

    struct NsLookup{};
    struct ClientLookup{};

    struct VisitorForStart{
        void operator()(ClientLookup& /**/) const;
        void operator()(NsLookup& /**/) const;

        LookupHandler* handler;
    };

    struct VisitorForFinishedRequest{
        void operator()(ClientLookup& /**/) const;
        void operator()(NsLookup& /**/) const;

        LookupHandler* handler;
        DnsPacket& packet;
        std::size_t response_size;
    };

    struct VisitorForContainsAdditional{
        void operator()(ClientLookup& /**/) const;
        void operator()(NsLookup& /**/) const;

        LookupHandler* handler;
        DnsPacket& packet;
    };

    private:
        std::variant<NsLookup,ClientLookup> lookupState;
        LookupTarget client;
        LookupServer server;
        InnerLookupTarget unresolved_server;
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

