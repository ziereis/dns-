//
// Created by thomas on 05.02.23.
//

#include "DnsServer.h"

#include <utility>
#include "fmt/ranges.h"
#include "BufferParser.h"
#include <range/v3/all.hpp>

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
    : lookup_servers{{ip::address::from_string("8.8.8.8"), 53}}
    , lookupState{ClientLookup{}}
    , lookup_socket_{lookup_socket}
    , client_socket_{client_socket}
    , client_{client}
    , original_req_buf_{}
    , original_req_buf_size_{buf_view.size()}
    , buf_{}
    {
        std::memcpy(original_req_buf_.data(), buf_view.data(), buf_view.size());
    }

    void LookupHandler::lookupStateVisitorForStart::operator()(ClientLookup&) const {
        LOG("starting client lookup")
        handler->lookup_socket_.async_send_to(buffer(handler->original_req_buf_.data(), handler->original_req_buf_size_),
                                              handler->lookup_servers.top(), [me=handler->shared_from_this()](const auto& ec, std::size_t bytes_sent) {

        if (ec) throw std::system_error(ec);
        me->handle_lookup(ec, bytes_sent);});
    }

    void LookupHandler::lookupStateVisitorForStart::operator()(LookupHandler::NsLookup &) const {
        LOG("starting server lookup")
        handler->lookup_socket_.async_send_to(buffer(handler->buf_.data(), handler->buf_size_),
                                              handler->lookup_servers, [me=handler->shared_from_this()](const auto& ec, std::size_t bytes_sent) {

        if (ec) throw std::system_error(ec);
        me->handle_lookup(ec, bytes_sent);});
    }


    void LookupHandler::start()
    {
        std::visit(lookupStateVisitorForStart{this},lookupState);
    }

    void LookupHandler::handle_lookup(const boost::system::error_code &ec, std::size_t bytes_read) {

        LOG("handling lookup")
        lookup_socket_.async_receive(buffer(buf_), [me=shared_from_this()](const auto &ec, std::size_t bytes_read) {
            if (ec) throw std::system_error(ec);
            me->handle_server_response(ec, bytes_read);
        });
    }

    void LookupHandler::lookupStateVisitorForHandlingServerResponse::operator()(LookupHandler::ClientLookup &) const {
        handler->client_socket_.async_send_to(buffer(handler->buf_.data(), response_size), handler->client_, [](const auto &ec, std::size_t bytes_read) {
            if (ec) throw std::system_error(ec);

            std::cout << "return packet to client" << std::endl;
        });

    }

    void LookupHandler::lookupStateVisitorForHandlingServerResponse::operator()(LookupHandler::NsLookup &) const {

    }

    void LookupHandler::handle_server_response(const boost::system::error_code &ec, std::size_t bytes_read)
    {
        DnsPacket packet{buf_.data(), bytes_read};

        if ((!packet.answers.empty()
             && packet.header_.get_response_code() == static_cast<uint8_t>(ResponseCode::NOERROR))
            || packet.header_.get_response_code() == static_cast<uint8_t>(ResponseCode::NXDOMAIN)) {
            std::visit(lookupStateVisitorForHandlingServerResponse{this, bytes_read}, lookupState);
        } else if (packet.header_.addtional_count > 0) {
            auto name_servers = packet.get_resolved_ns(packet.questions[0].name);
            fmt::print("{}\n", name_servers | ranges::view::transform([](auto addr){return addr.to_string();}));
            server_.address(*name_servers.begin());
            start();
        } else if (packet.header_.addtional_count == 0 && packet.header_.authority_count > 0) {
            auto unresolved_ns = packet.get_unresolved_ns(packet.questions[0].name);
            fmt::print("{}\n", unresolved_ns);
            auto pkt = DnsPacket::generate(1, false, true);
            pkt.add_question(*unresolved_ns.begin(),1);
            BufferBuilder builder{pkt};
            auto buf = builder.build_and_get_buf();
        }

    }

}
