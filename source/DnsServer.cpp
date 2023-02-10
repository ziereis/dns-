//
// Created by thomas on 05.02.23.
//

#include "DnsServer.h"
namespace Dns
{
    DnsServer::DnsServer()
            : client_socket(io)
            , lookup_socket(io)
    {}

    void DnsServer::start_server(uint16_t port)
    {
        boost::system::error_code ec;

        ip::udp::endpoint client_ep(ip::address_v4::any(), port);
        client_socket.open(ip::udp::v4(), ec);
        client_socket.bind(client_ep, ec);

        ip::udp::endpoint server_ep(ip::address_v4::any(), 52346);
        lookup_socket.open(ip::udp::v4(), ec);
        lookup_socket.bind(client_ep, ec);

        std::array<uint8_t, DNS_BUF_SIZE> buf{};
        client_socket.async_receive_from(buffer(buf), client, [&buf, this] (const auto& ec, std::size_t bytes_read){
            handle_incoming_request(ec, bytes_read, buf);
        });

        io.run();
    }



    void DnsServer::lookup(std::array<uint8_t, DNS_BUF_SIZE> buf)
    {
        ip::udp::endpoint name_server(ip::address::from_string("198.41.0.4"), 53);

        lookup_socket.async_send_to(buffer(buf), name_server, [this](const auto&ec, size_t bytes_sent) {
            handle_lookup(ec, bytes_sent);});


    }

    void DnsServer::handle_incoming_request(const boost::system::error_code& ec,
                                 size_t bytes_read,
                                 std::array<uint8_t, DNS_BUF_SIZE> buf)
    {
        if(ec) return;

        Dns::DnsPacket packet{buf, bytes_read};

        lookup(buf);

        client_socket.async_receive_from(buffer(buf), client, [&buf, this](const auto& ec, std::size_t bytes_read){
            handle_incoming_request(ec, bytes_read, buf);
        });

    }

    void DnsServer::handle_lookup(const boost::system::error_code &ec, size_t bytes_read) {

        std::array<uint8_t, DNS_BUF_SIZE> buf{};

        lookup_socket.async_receive(buffer(buf), [&buf, this] (const auto& ec, std::size_t bytes_read){
            handle_server_response(ec, bytes_read, buf);
        });


    }


    void DnsServer::handle_server_response(const boost::system::error_code &ec, size_t bytes_read,
                                           std::array<uint8_t, DNS_BUF_SIZE> buf) {
        Dns::DnsPacket packet{buf, bytes_read};

        if (!packet.answers.empty()) {
            client_socket.async_send_to(buffer(buf), client, [](const auto &ec, std::size_t bytes_read) {
                std::cout << "return packet to client" << std::endl;
            });
        } else if (!packet.additionals.empty()) {
            auto& additional = packet.additionals.back();
            std::visit(RecordPrintVisitor{},additional.record);
        }
    }


}
