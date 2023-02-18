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
    std::array<ip::udp::endpoint, 13> generate_root_server_eps(std::span<const std::string_view> ips) {
        std::array<ip::udp::endpoint,13> result{};
        std::transform(ips.begin(), ips.end(), result.begin(), [](auto str_view) {
            return ip::udp::endpoint(ip::address::from_string(str_view.data()),53);
        });
        return result;
    }
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
                                 ip::udp::socket& client_socket, ip::udp::endpoint client_ep)
    : lookupState{ClientLookup{}}
    , client{std::move(client_ep), {root_server_eps.begin(), root_server_eps.end()}, {}, buf_view.size(), client_socket}
    , server{client.available_endpoints_.front(), {}, lookup_socket}
    , unresolved_server{{},server.buf_, lookup_socket}

    {
        std::memcpy(client.buf_.data(), buf_view.data(), buf_view.size());
    }

    void LookupHandler::VisitorForStart::operator()(ClientLookup&) const {
        LOG("starting client lookup")
        handler->server.socket_.async_send_to(buffer(handler->client.buf_.data(), handler->client.buf_size_),
                                              handler->server.ep_, [me=handler->shared_from_this()](const auto& ec, std::size_t bytes_sent) {

        if (ec) throw std::system_error(ec);
        me->handle_lookup(ec, bytes_sent);});
    }

    void LookupHandler::VisitorForStart::operator()(LookupHandler::NsLookup &) const {
        LOG("starting server lookup")
        handler->server.socket_.async_send_to(buffer(handler->unresolved_server.buf_view_.data(), handler->unresolved_server.buf_view_.size()),
                                              handler->server.ep_, [me=handler->shared_from_this()](const auto& ec, std::size_t bytes_sent) {

            if (ec) throw std::system_error(ec);
            me->handle_lookup(ec, bytes_sent);
        });
    }

    void LookupHandler::start()
    {
        std::visit(VisitorForStart{this},lookupState);
    }

    void LookupHandler::handle_lookup(const boost::system::error_code &ec, std::size_t bytes_sent) {

        LOG("handling lookup")
        server.socket_.async_receive(buffer(server.buf_), [me=shared_from_this()](const auto &ec, std::size_t bytes_read) {
            if (ec) throw std::system_error(ec);
            me->handle_server_response(ec, bytes_read);
        });
    }

    void LookupHandler::VisitorForFinishedRequest::operator()(LookupHandler::ClientLookup &) const {
        handler->client.socket_.async_send_to(buffer(handler->server.buf_.data(), response_size),
                                              handler->client.ep_, [](const auto &ec, std::size_t bytes_read) {
            if (ec) throw std::system_error(ec);
            std::cout << "return packet to client" << std::endl;
        });

    }

    void LookupHandler::VisitorForFinishedRequest::operator()(LookupHandler::NsLookup &) const {
        auto answers = packet.get_answers();
        std::move(answers.begin(), answers.end(),
                  std::front_inserter(handler->client.available_endpoints_));
        handler->lookupState = ClientLookup{};
        handler->server.ep_ = handler->client.available_endpoints_.front();
        handler->start();
    }

    void LookupHandler::VisitorForContainsAdditional::operator()(LookupHandler::ClientLookup &) const {
        handler->handle_contains_additional(handler->client, packet);
    }

    void LookupHandler::VisitorForContainsAdditional::operator()(LookupHandler::NsLookup &) const {
        handler->handle_contains_additional(handler->unresolved_server, packet);
    }

    template<typename T>
    requires std::is_same_v<T, LookupTarget> || std::is_same_v<T, InnerLookupTarget>
    void LookupHandler::handle_contains_additional(T &target, const DnsPacket& packet) {
        fmt::print("{}\n", packet.questions.front().name);
        auto name_servers = packet.get_resolved_ns(packet.questions.front().name);
        fmt::print("ns :{}\n", name_servers | ranges::view::transform([](auto addr){return addr.to_string();}));
        auto eps = name_servers | ranges::view::transform([](auto addr){return ip::udp::endpoint(addr,53);});
        target.available_endpoints_.pop_front();
        std::move(eps.begin(), eps.end(),
                  std::front_inserter(target.available_endpoints_));
        server.ep_ = target.available_endpoints_.front();
        start();
    }

    void LookupHandler::handle_server_response(const boost::system::error_code &ec, std::size_t bytes_read)
    {
        DnsPacket packet{server.buf_.data(), bytes_read};

        if ((!packet.answers.empty()
             && packet.header_.get_response_code() == static_cast<uint8_t>(ResponseCode::NOERROR))
            || packet.header_.get_response_code() == static_cast<uint8_t>(ResponseCode::NXDOMAIN)) {
            std::visit(VisitorForFinishedRequest{this, packet, bytes_read}, lookupState);
        } else if (packet.header_.addtional_count > 0) {
            std::visit(VisitorForContainsAdditional{this, packet}, lookupState);
        } else if (packet.header_.addtional_count == 0 && packet.header_.authority_count > 0) {
            auto unresolved_ns = packet.get_unresolved_ns(packet.questions.front().name);
            fmt::print("{}\n", unresolved_ns);
            auto pkt = DnsPacket::generate(1, false, true);
            pkt.add_question(DnsQuestion{*unresolved_ns.begin(), 1,1});
            BufferBuilder builder{pkt};
            auto buf = builder.build_and_get_buf();
            lookupState = NsLookup{};

            std::memcpy(server.buf_.data(), buf.data(), buf.size());
            unresolved_server.buf_view_ = std::span(server.buf_.data(), buf.size());


        }

    }


}
