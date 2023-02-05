#include <boost/asio.hpp>
#include "DnsServer.h"

int main()
{
    auto server = Dns::DnsServer();

    server.start_server(2053);

}
