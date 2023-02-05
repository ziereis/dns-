//
// Created by thomas on 05.02.23.
//

#include "DnsServer.h"
namespace Dns
{
    DnsServer::DnsServer(int thread_count)
            : thread_count{thread_count}
            , socket(io)
    {}

    void DnsServer::start_server(uint16_t port)
    {
        boost::system::error_code ec;

        ip::udp::endpoint ep(ip::address_v4::any(), port);
        socket.open(ip::udp::v4(), ec);
        socket.bind(ep, ec);

        std::array<uint8_t, DNS_BUF_SIZE> buf{};
        socket.async_receive(buffer(buf), [&buf, this] (const auto& ec, std::size_t bytes_read){
            handle_incoming_request(ec, bytes_read, buf);
        });

        io.run();
    }

    void DnsServer::handle_incoming_request(const boost::system::error_code& ec,
                                 size_t bytes_read,
                                 std::array<uint8_t, DNS_BUF_SIZE> buf)
    {
        if(ec) return;

        Dns::DnsPacket packet(buf, bytes_read);

        socket.async_receive(buffer(buf), [&buf, this](const auto& ec, std::size_t bytes_read){
            handle_incoming_request(ec, bytes_read, buf);
        });

    }

}
