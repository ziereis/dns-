#include "DnsServer.h"
#include "BufferParser.h"

struct process {
    ip::udp::socket& socket;
    uint8_t* buf;
    std::size_t size_;
    void operator()(boost::system::error_code ec, std::size_t bytes)
    {
        if (ec) throw std::system_error(ec);

        Dns::DnsPacket packet{buf, size_, bytes};
        std::cout << packet;

        initiate();
    }
    void initiate() {
        socket.async_receive(buffer(buf, size_), std::move(*this));
    }




};

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

    uint8_t recv_buf[DNS_BUF_SIZE];

    socket.async_send_to(buffer(buf), server,[](const auto& ec,  auto aa){ std::cout << "sent\n";});


    process{socket, recv_buf, DNS_BUF_SIZE}.initiate();
    ctx.run();
*/
}
