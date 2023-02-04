#include <boost/asio.hpp>
#include "Dns.h"

using namespace boost::asio;


int main()
{
    ip::udp::endpoint ep(ip::address_v4::any(), 2053);

    io_context io;

    boost::system::error_code error_code;

    ip::udp::socket socket(io);
    socket.open(ip::udp::v4(), error_code);
    socket.bind(ep, error_code);


    std::array<uint8_t, DNS_BUF_SIZE> buf{};
    socket.async_receive(buffer(buf), [](const auto& ec, const auto bytes_read){
        if (!ec) std::printf("recieved %ld\n", bytes_read);});

    io.run();

    Dns::DnsPacket packet(buf, 50);

}
