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
    std::array<uint32_t, 13> generate_root_server_ipv4s(std::span<const std::string_view> ips) {
        std::array<uint32_t,13> result{};
        std::transform(ips.begin(), ips.end(), result.begin(), [](auto str_view) {
            return ip::address_v4::from_string(str_view.data()).to_uint();
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
            fmt::print("Handling lookup for: {}\n", client->address().to_string());
            DnsPacket packet{buf_, bytes_read};

            fmt::print("with the Questions\n");

            for (const auto& q : packet.questions) {
                std::cout << q << std::endl;
            }

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
    , client{std::move(client_ep), {}, {}, {root_server_ip4s.begin(), root_server_ip4s.end()}, {}, buf_view.size(), client_socket}
    , server{{}, {}, lookup_socket}

    , unresolved_server{{},{},{},{},0}

    {
        std::memcpy(client.buf_.data(), buf_view.data(), buf_view.size());
    }

    void LookupHandler::VisitorForStart::operator()(ClientLookup&) const {
        LOG("starting client lookup")
        handler->add_endpoint_to_server(handler->client);
        fmt::print("visited endpoints: {}\n", handler->client.visited_endpoints);
        fmt::print("available endpoints: {}\n", handler->client.available_endpoints_);
        handler->server.socket_.async_send_to(buffer(handler->client.buf_.data(), handler->client.buf_size_),
                                              handler->server.ep_, [me=handler->shared_from_this()](const auto& ec, std::size_t bytes_sent) {

        if (ec) throw std::system_error(ec);
        me->handle_lookup(ec, bytes_sent);});
    }

    void LookupHandler::VisitorForStart::operator()(LookupHandler::NsLookup &) const {
        LOG("starting server lookup")
        handler->add_endpoint_to_server(handler->unresolved_server);
        handler->server.socket_.async_send_to(buffer(handler->unresolved_server.buf_.data(), handler->unresolved_server.buf_size_),
                                              handler->server.ep_, [me=handler->shared_from_this()](const auto& ec, std::size_t bytes_sent) {

            if (ec) throw std::system_error(ec);
            me->handle_lookup(ec, bytes_sent);
        });
    }

    template<typename T>
    requires std::is_same_v<T, LookupTarget> || std::is_same_v<T, InnerLookupTarget>
    void LookupHandler::add_endpoint_to_server(T& target) {
        server.ep_ = ip::udp::endpoint(
                ip::address_v4{target.available_endpoints_.front()}, 53);
        target.visited_endpoints.insert(target.available_endpoints_.front());
        target.available_endpoints_.pop_front();
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
        LOG("unresolved server lookup finished");
        auto answers = packet.get_answers();
        fmt::print("{}\n", answers | ranges::views::transform([](auto s){return s.to_string();}));
        auto uints = answers
        | ranges::views::transform([](auto&& ipAddr) {
                    return ipAddr.to_uint();
                });
        std::copy_if(uints.begin(),  uints.end(), std::front_inserter(handler->client.available_endpoints_),
                     [&visited_endpoints = handler->client.visited_endpoints](auto ipAddr) {
                    return visited_endpoints.find(ipAddr) == visited_endpoints.end();
        });
        handler->lookupState = ClientLookup{};
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
        auto name_servers = packet.get_resolved_ns(packet.questions.front().name);
        fmt::print("{}\n", name_servers | ranges::views::transform([](auto s){return s.to_string();}));
        auto ips = name_servers
                | ranges::view::transform([](auto&& addr){ return addr.to_uint();});
        std::copy_if(ips.begin(), ips.end(), std::front_inserter(target.available_endpoints_),
                     [&visited_endpoints = target.visited_endpoints](auto ipAddr) {
                         return visited_endpoints.find(ipAddr) == visited_endpoints.end();
                     });
        start();
    }

    void LookupHandler::handle_server_response(const boost::system::error_code &ec, std::size_t bytes_read)
    {
        DnsPacket packet{server.buf_.data(), bytes_read};
        //LOG(packet);
        if ((!packet.answers.empty()
             && packet.header_.get_response_code() == static_cast<uint8_t>(ResponseCode::NOERROR))
            || packet.header_.get_response_code() == static_cast<uint8_t>(ResponseCode::NXDOMAIN)) {
                std::visit(VisitorForFinishedRequest{this, packet, bytes_read}, lookupState);
        } else if (packet.header_.addtional_count > 0) {
            LOG("handling additional")
            std::visit(VisitorForContainsAdditional{this, packet}, lookupState);
        } else if (packet.header_.addtional_count == 0 && packet.header_.authority_count > 0) {
            LOG("handling no additional")
            auto unresolved_ns = packet.get_unresolved_ns(packet.questions.front().name)
                    | ranges::views::filter([this](auto name) {
                        return  client.visited_names.find(name) == client.visited_names.end();
                    });

            if (unresolved_ns.empty())
                throw std::runtime_error{"no more names to resolve"};
            client.visited_names.insert(*unresolved_ns.begin());
            fmt::print("{}\n", unresolved_ns);
            auto pkt = DnsPacket::generate(1, false, true);
            pkt.add_question(DnsQuestion{*unresolved_ns.begin(), 1,1});
            BufferBuilder builder{pkt};
            auto buf = builder.build_and_get_buf();
            lookupState = NsLookup{};


            std::memcpy(unresolved_server.buf_.data(), buf.data(), buf.size());
            unresolved_server.buf_size_ = buf.size();
            unresolved_server.available_endpoints_ = {};
            unresolved_server.visited_endpoints = {};
            unresolved_server.available_endpoints_ = {root_server_ip4s.begin(), root_server_ip4s.end()};
            start();
        }

    }


}
