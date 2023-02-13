#include "DnsServer.h"
#include "BufferParser.h"

int main()
{
    auto server = Dns::DnsServer();

    server.start_server(2053);
/*
    io_context ctx;
    boost::system::error_code ec;
    ip::udp::socket socket(ctx);

    ip::udp::endpoint me(ip::address::from_string("0.0.0.0"), 991);
    ip::udp::endpoint server(ip::address::from_string("1.1.1.1"), 53);

    socket.open(ip::udp::v4(), ec);
    socket.bind(me, ec);


    auto packet = Dns::DnsPacket::generate(10, false, false);
    packet.add_question("google.com", 1);
    Dns::BufferBuilder builder{packet};
    auto buf = builder.build_and_get_buf();

    socket.async_send_to(buffer(buf), server, [&socket](const auto& ec, auto bytes){
        std::array<uint8_t, DNS_BUF_SIZE> recv_buf{};
        socket.async_receive(buffer(recv_buf),[recv_buf](const boost::system::error_code& ec, size_t bytes){
            Dns::DnsPacket in_packet{recv_buf, bytes};
            std::cout << in_packet.header_;
        });
    });

    ctx.run();
*/
}
