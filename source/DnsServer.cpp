//
// Created by thomas on 05.02.23.
//

#include "DnsServer.h"
#include "fmt/core.h"
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

        ip::udp::endpoint server_ep(ip::address_v4::any(), 5234);
        lookup_socket.open(ip::udp::v4(), ec);
        lookup_socket.bind(client_ep, ec);

        std::array<uint8_t, DNS_BUF_SIZE> buf{};

        ip::udp::endpoint client;
        client_socket.async_receive_from(buffer(buf), client, [&buf, this, &client] (const auto& ec, std::size_t bytes_read){
            handle_incoming_request(ec, bytes_read, buf, client);
        });

        io.run();
    }



    void DnsServer::lookup(std::array<uint8_t, DNS_BUF_SIZE> buf, ip::udp::endpoint client)
    {
        ip::udp::endpoint name_server(ip::address::from_string("8.8.8.8"), 53);

        LOG("performing lookup for client: " + client.address().to_string() + "\n");
        LOG("performing lookup on server: " + name_server.address().to_string() + "\n");
        lookup_socket.async_send_to(buffer(buf), name_server, [this, &client](const auto&ec, size_t bytes_sent) {
            handle_lookup(ec, bytes_sent, client);});
    }

    void DnsServer::handle_incoming_request(const boost::system::error_code& ec,
                                 size_t bytes_read,
                                 std::array<uint8_t, DNS_BUF_SIZE> buf, ip::udp::endpoint client)
    {
        if(ec) return;
        LOG("received from client: " + client.address().to_string() + "\n");
        Dns::DnsPacket packet{buf, bytes_read};
        lookup(buf, client);

        client_socket.async_receive_from(buffer(buf), client, [&buf, this, &client](const auto& ec, std::size_t bytes_read){
            handle_incoming_request(ec, bytes_read, buf, client);
        });

    }

    void DnsServer::handle_lookup(const boost::system::error_code &ec, size_t bytes_read,
                                  ip::udp::endpoint client) {

        std::array<uint8_t, DNS_BUF_SIZE> buf{};

        LOG("receiving from dns server for client: " + client.address().to_string() + "\n");
        lookup_socket.async_receive(buffer(buf), [&buf, this, &client] (const auto& ec, std::size_t bytes_read){
            handle_server_response(ec, bytes_read, buf, client);
        });


    }


    void DnsServer::handle_server_response(const boost::system::error_code &ec, size_t bytes_read,
                                           std::array<uint8_t, DNS_BUF_SIZE> buf, ip::udp::endpoint client) {

        LOG("handling answer from dns server for client: " + client.address().to_string() + "\n");
        Dns::DnsPacket packet{buf, bytes_read};
        LOG("finished parsing packet\n")

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
