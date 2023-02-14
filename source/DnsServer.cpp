//
// Created by thomas on 05.02.23.
//

#include "DnsServer.h"

#include <utility>
#include "fmt/core.h"
namespace Dns
{
    struct client_request_handler{
        ip::udp::socket& client_socket_;
        ip::udp::socket& lookup_socket_;
        uint8_t* buf_;
        std:: size_t buf_size_;
        ip::udp::endpoint* client;

        void operator()(boost::system::error_code ec, std::size_t bytes_read)
        {
            if (ec) throw std::system_error(ec);
            auto lookup_handler = std::make_shared<LookupHandler>(
                    std::span<uint8_t>(buf_, bytes_read),  lookup_socket_, client_socket_, *client);
            lookup_handler->start();

            initiate();
        }

        void initiate()
        {
            client_socket_.async_receive_from(buffer(buf_, buf_size_), *client, std::move(*this));
        }
    };

    DnsServer::DnsServer()
            : client_socket(ctx)
            , lookup_socket(ctx)
            , buf{}
    {}

    void DnsServer::start_server(uint16_t port)
    {
        boost::system::error_code ec;

        ip::udp::endpoint client_ep(ip::address_v4::any(), port);
        client_socket.open(ip::udp::v4(), ec);
        client_socket.bind(client_ep, ec);

        ip::udp::endpoint server_ep(ip::address_v4::any(), 5234);
        lookup_socket.open(ip::udp::v4(), ec);
        lookup_socket.bind(server_ep, ec); //lol


        ip::udp::endpoint client;
        client_request_handler{client_socket, lookup_socket, buf.data(), buf.size(), &client}.initiate();
        ctx.run();
    }

    LookupHandler::LookupHandler(std::span<const uint8_t> buf_view, ip::udp::socket& lookup_socket,
                                 ip::udp::socket& client_socket, ip::udp::endpoint client)
    : lookup_socket_{lookup_socket}
    , client_socket_{client_socket}
    , client_{client}
    , server_{ip::address::from_string("8.8.8.8"), 53}
    , buf_{}
    {
        std::memcpy(buf_.data(), buf_view.data(), buf_view.size());
    }

    void LookupHandler::start()
    {
        lookup_socket_.async_send_to(buffer(buf_), server_, [me=shared_from_this()](const auto&ec, std::size_t bytes_sent) {
            if (ec) throw std::system_error(ec);
            me->handle_lookup(ec, bytes_sent);});
    }

    void LookupHandler::handle_lookup(const boost::system::error_code &ec, std::size_t bytes_read) {

        lookup_socket_.async_receive(buffer(buf_), [me=shared_from_this()](const auto &ec, std::size_t bytes_read) {
            if (ec) throw std::system_error(ec);
            me->handle_server_response(ec, bytes_read);
        });
    }

    void LookupHandler::handle_server_response(const boost::system::error_code &ec, std::size_t bytes_read)
    {

        Dns::DnsPacket packet{buf_, bytes_read};

        LOG(packet);
        LOG(client_);
        if (!packet.answers.empty()) {
            client_socket_.async_send_to(buffer(buf_), client_, [](const auto &ec, std::size_t bytes_read) {
                if (ec) throw std::system_error(ec);

                std::cout << "return packet to client" << std::endl;
            });
        } else if (!packet.additionals.empty()) {
            auto& additional = packet.additionals.back();
            std::visit(RecordPrintVisitor{},additional.record);
        }
    }

}
