//
// Created by thomas on 04.02.23.
//

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include <numeric>
#include <ranges>
#include "doctest/doctest.h"
#include "BufferParser.h"
#include <boost/asio.hpp>
#include "bitset"
#include <boost/asio.hpp>

using namespace boost::asio;

TEST_CASE("BufferParser read") {
    SUBCASE("uint8_t")
    {
        std::array<uint8_t,1> buf{0b0101'1101};
        uint8_t reference = static_cast<uint8_t>(buf[0]);
        Dns::BufferParser parser{std::span(buf)};
        auto parsed =  parser.read<uint8_t>();
        INFO("reference Value: ", std::bitset<8>(reference));
        INFO("parsed Value: ", std::bitset<8>(parsed));
        CHECK((reference == parsed));
    }
    SUBCASE("uint16_t")
    {
        std::array<uint8_t,2> buf{0b0101'1101, 0b0100'0010};
        uint16_t reference = static_cast<uint16_t>(buf[0]) << 8 | static_cast<uint16_t>(buf[1]);
        Dns::BufferParser parser{std::span(buf)};
        auto parsed =  parser.read<uint16_t>();
        INFO("reference Value: ", std::bitset<16>(reference));
        INFO("parsed Value: ", std::bitset<16>(parsed));
        CHECK((reference == parsed));
    }

    SUBCASE("uint32_t")
    {
        std::array<uint8_t,4> buf{0b0101'1101, 0b0100'0010, 0b0000'0001, 0b0010'1101};
        uint32_t reference = static_cast<uint32_t>(buf[0]) << 24
                | static_cast<uint32_t>(buf[1]) << 16
                | static_cast<uint32_t>(buf[2]) << 8
                | static_cast<uint32_t>(buf[3]);
        Dns::BufferParser parser{std::span(buf)};
        auto parsed =  parser.read<uint32_t>();
        INFO("reference Value: ", std::bitset<32>(reference));
        INFO("parsed Value: ", std::bitset<32>(parsed));
        CHECK((reference == parsed));
    }
    SUBCASE("consecutive Reads")
    {
        std::array<uint8_t,4> buf{0b0101'1101, 0b0100'0010, 0b0000'0001, 0b0010'1101};
        uint16_t first_ref = static_cast<uint16_t>(buf[0]) << 8 | static_cast<uint16_t>(buf[1]);
        uint16_t second_ref = static_cast<uint16_t>(buf[2]) << 8 | static_cast<uint16_t>(buf[3]);

        Dns::BufferParser parser{std::span(buf)};
        auto first_parsed =  parser.read<uint16_t>();
        auto second_parsed =  parser.read<uint16_t>();
        CHECK((first_parsed == first_ref));
        CHECK((second_parsed == second_ref));
    }
}

TEST_CASE("packet building")
{
    SUBCASE("question")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        packet.add_question(Dns::DnsQuestion{"google.com", 1,1});

        CHECK_EQ(10, packet.header_.id);
        CHECK_EQ(1, packet.header_.question_count);
        CHECK_EQ("google.com", packet.questions[0].name);

    }
    SUBCASE("answer") {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::DnsAnswer answer{"google.com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::A{15612}};
        packet.add_answer(std::move(answer));

        CHECK_EQ(10, packet.header_.id);
        CHECK_EQ(1, packet.header_.answer_count);
        CHECK_EQ("google.com", packet.answers.front().name);
        CHECK_EQ(ip::address_v4{15612}, std::get<Dns::DnsAnswer::A>(packet.answers.front().record).ip4Addr);
    }
    SUBCASE("authority")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::DnsAnswer answer{"google.com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::NS{"glabl.yam"}};
        packet.add_authority(std::move(answer));

        CHECK_EQ(10, packet.header_.id);
        CHECK_EQ(1, packet.header_.authority_count);
        CHECK_EQ("google.com", packet.authorities.front().name);
        CHECK_EQ("glabl.yam", std::get<Dns::DnsAnswer::NS>(packet.authorities.front().record).name);
    }
    SUBCASE("additional")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::DnsAnswer answer{"google.com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::A{15612}};
        packet.add_additional(std::move(answer));

        CHECK_EQ(10, packet.header_.id);
        CHECK_EQ(1, packet.header_.addtional_count);
        CHECK_EQ(1, packet.additionals.size());
        CHECK_EQ("google.com", packet.additionals.front().name);
        CHECK_EQ(ip::address_v4{15612}, std::get<Dns::DnsAnswer::A>(packet.additionals.front().record).ip4Addr);
    }

}

TEST_CASE("buffer generation from packet")
{
    SUBCASE("write uint16")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::BufferBuilder builder{packet};
        builder.write<uint16_t>(63001);
        auto buf = builder.get_buf();

        Dns::BufferParser parser{buf};

        auto val = parser.read<uint16_t>();

        CHECK_EQ(63001, val);
    }
    SUBCASE("write multiple")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::BufferBuilder builder{packet};
        builder.write<uint16_t>(63001);
        builder.write<uint8_t>(14);
        builder.write<uint8_t>(20);
        builder.write<uint32_t>(17012345);
        builder.write<std::byte>(std::byte(20));
        builder.write<uint16_t>(999);
        auto buf = builder.get_buf();

        Dns::BufferParser parser{buf};

        auto val = parser.read<uint16_t>();
        auto val2 = parser.read<uint8_t>();
        auto val3 = parser.read<uint8_t>();
        auto val4 = parser.read<uint32_t>();
        auto val5 = parser.read<uint8_t>();
        auto val6 = parser.read<uint16_t>();

        CHECK_EQ(63001, val);
        CHECK_EQ(14, val2);
        CHECK_EQ(20, val3);
        CHECK_EQ(17012345, val4);
        CHECK_EQ(20, val5);
        CHECK_EQ(999, val6);
    }

    SUBCASE("write name")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::BufferBuilder builder{packet};
        builder.write_name("testname.ggg");
        builder.write<uint8_t>(15);
        auto buf = builder.get_buf();

        Dns::BufferParser parser{buf};

        auto val = parser.read_name();
        auto val2 = parser.read<uint8_t>();

        CHECK_EQ("testname.ggg", val);
        CHECK_EQ(15, val2);
    }
    SUBCASE("write default_packet")
    {
        auto packet = Dns::DnsPacket::generate(10, true, true);
        packet.add_question(Dns::DnsQuestion{"google.com", 1,1});
        Dns::BufferBuilder builder{packet};
        auto buf = builder.build_and_get_buf();

        Dns::BufferParser parser{buf};

        auto header = parser.read_header();
        auto question = parser.read_question();
        INFO(packet.header_);
        INFO(packet.questions[0]);
        INFO(header);
        INFO(question);
        CHECK_EQ(10, header.id);
        CHECK_EQ(true, header.get_recursion_desired());
        CHECK_EQ(true, header.get_query_response());
        CHECK_EQ("google.com", question.name);
        CHECK_EQ(1, question.query_type);
    }

    SUBCASE("write and parse")
    {
        auto packet = Dns::DnsPacket::generate(10, true, true);
        packet.add_question(Dns::DnsQuestion{"google.com", 1,1});
        Dns::BufferBuilder builder{packet};
        auto buf = builder.build_and_get_buf();

        Dns::DnsPacket pkt{buf.data(),buf.size()};

        CHECK_EQ(pkt.questions.front().name, "google.com");

    }

}

TEST_CASE("requests")
{
        SUBCASE("default_request"){
        io_context ctx;
        boost::system::error_code ec;
        ip::udp::socket socket(ctx);

        ip::udp::endpoint me(ip::address_v4::any(), 994);
        ip::udp::endpoint server(ip::address::from_string("1.1.1.1"), 53);

        socket.open(ip::udp::v4(), ec);
        socket.bind(me, ec);

        auto packet = Dns::DnsPacket::generate(10, false, true);
        packet.add_question(Dns::DnsQuestion{"google.com", 1,1});
        Dns::BufferBuilder builder{packet};
        auto buf = builder.build_and_get_buf();

        socket.send_to(buffer(buf.data(), buf.size()), server);

        std::cout << "waiting" << std::endl;

        std::array<uint8_t, DNS_BUF_SIZE> recv_buf{};
        size_t bytes_received = socket.receive(buffer(recv_buf));

        Dns::DnsPacket in_packet{recv_buf.data(), bytes_received};
        INFO(packet);
        INFO(in_packet);
        CHECK_EQ(in_packet.header_.answer_count, 1);
    }
    SUBCASE("root ns query")
    {
        io_context ctx;
        boost::system::error_code ec;
        ip::udp::socket socket(ctx);

        ip::udp::endpoint me(ip::address_v4::any(), 992);
        ip::udp::endpoint server(ip::address::from_string("198.41.0.4"), 53);

        socket.open(ip::udp::v4(), ec);
        socket.bind(me, ec);

        auto packet = Dns::DnsPacket::generate(10, false, true);
        packet.add_question(Dns::DnsQuestion{"google.com", 1,1});
        Dns::BufferBuilder builder{packet};
        auto buf = builder.build_and_get_buf();

        socket.send_to(buffer(buf.data(), buf.size()), server);

        std::cout << "waiting" << std::endl;

        std::array<uint8_t, DNS_BUF_SIZE> recv_buf{};
        size_t bytes_received = socket.receive(buffer(recv_buf));

        Dns::DnsPacket in_packet{recv_buf.data(), bytes_received};
        INFO(packet);
        INFO(in_packet);
        CHECK_EQ(0,  in_packet.header_.get_response_code());
        CHECK_EQ(in_packet.header_.authority_count, 13);
    }

    SUBCASE("sub root ns query")
    {
        io_context ctx;
        boost::system::error_code ec;
        ip::udp::socket socket(ctx);

        ip::udp::endpoint me(ip::address_v4::any(), 991);
        ip::udp::endpoint server(ip::address::from_string("192.5.6.30"), 53);

        socket.open(ip::udp::v4(), ec);
        socket.bind(me, ec);

        auto packet = Dns::DnsPacket::generate(10, false, true);
        packet.add_question(Dns::DnsQuestion{"google.com", 1, 1});
        Dns::BufferBuilder builder{packet};
        auto buf = builder.build_and_get_buf();

        socket.send_to(buffer(buf.data(), buf.size()), server);

        std::cout << "waiting" << std::endl;

        std::array<uint8_t, DNS_BUF_SIZE> recv_buf{};
        size_t bytes_received = socket.receive(buffer(recv_buf));

        Dns::DnsPacket in_packet{recv_buf.data(), bytes_received};
        INFO(packet);
        INFO(in_packet);
        CHECK_EQ(0,  in_packet.header_.get_response_code());
        CHECK_EQ(in_packet.header_.authority_count, 4);
    }
}

std::vector<uint8_t> generate_buffer_from_label_vec(std::span<std::string> domain)
{
    std::vector<uint8_t> buf;
    for (auto& label : domain)
    {
        buf.push_back(label.size());
        for (char c : label)
            buf.push_back(c);
    }
    buf.push_back(0);

    return buf;
}

TEST_CASE("bit getters and setter")
{
    SUBCASE("setters")
    {
       uint8_t num = 0;

        Dns::set_bits_at_offsets(num, 1, 4, 6);
        CHECK_EQ(0b0101'0010, num);

    }

    SUBCASE("setters should throw")
    {
        uint8_t num = 0;

        CHECK_THROWS(Dns::set_bits_at_offsets(num, 8));
    }

    SUBCASE("getter")
    {
        uint8_t num = 0b1010'0100;

        auto flags = Dns::get_bits_at_offsets(num, 7, 2, 0);

        CHECK_EQ(0b1000'0100, flags);

    }

    SUBCASE("getter should throw")
    {
        uint8_t num = 0;

        CHECK_THROWS(Dns::get_bits_at_offsets(num, 8));
    }
}

TEST_CASE("BufferParser read_header")
{
    const std::array<uint8_t, 12> buf
            {0, 0b0000'1000, 0b1000'0001, 0b1000'1000, 0, 1, 0, 1, 0, 1, 0, 1};

    Dns::BufferParser parser{std::span(buf)};
    auto header = parser.read_header();
    auto ref_id = parser.get<uint16_t>(0);
    INFO("reference Value: ", std::bitset<8>(8));
    INFO("real Value: ", header);
    CHECK_EQ(ref_id, header.id);
    CHECK_EQ(1, header.get_query_response());
    CHECK_EQ(0, header.get_op_code());
    CHECK_EQ(0, header.get_authoritative_answer());
    CHECK_EQ(0, header.get_truncated_message());
    CHECK_EQ(1, header.get_recursion_desired());
    CHECK_EQ(1, header.get_recursion_available());
    CHECK_EQ(0, header.get_reserved());
    CHECK_EQ(8, header.get_response_code());
    CHECK_EQ(1, header.question_count);
    CHECK_EQ(1, header.answer_count);
    CHECK_EQ(1, header.authority_count);
    CHECK_EQ(1, header.addtional_count);
}
TEST_CASE("BufferParser read_name")
{
    SUBCASE("single_name")
    {
        std::vector<std::string> domain{"www", "coolio","com"};
        auto buf = generate_buffer_from_label_vec(domain);
        buf.push_back(1);
        Dns::BufferParser parser{std::span(buf)};
        auto name = parser.read_name();
        auto val = parser.read<uint8_t>();
        auto ref_name = std::accumulate(domain.begin(), domain.end(), std::string{}, [](auto sum, auto str)
            { return sum + str + ".";});
        ref_name.pop_back();
        INFO("reference Value: ", ref_name);
        INFO("parsed Value: ", name);
        CHECK_EQ(name,ref_name);
        CHECK_EQ(1,val);
    }

    SUBCASE("empty_name")
    {
        std::vector<std::string> domain{""};
        auto buf = generate_buffer_from_label_vec(domain);
        Dns::BufferParser parser{std::span(buf)};
        auto name = parser.read_name();
        auto ref_name = std::accumulate(domain.begin(), domain.end(), std::string{}, [](auto sum, auto str)
        { return sum + str + ".";});
        ref_name.pop_back();
        INFO("reference Value: ", ref_name);
        INFO("parsed Value: ", name);
        CHECK((name == ref_name));
    }
    SUBCASE("read_name with jumps")
    {
        std::vector<uint8_t> buf;
        buf.push_back(5);
        buf.push_back('a');
        buf.push_back('b');
        buf.push_back('c');
        buf.push_back('d');
        buf.push_back('e');
        buf.push_back(3);
        buf.push_back('x');
        buf.push_back('y');
        buf.push_back('z');
        buf.push_back(0);
        buf.push_back(0b1100'0000);
        buf.push_back(0b000'0000);
        buf.push_back(0b1100'0000);
        buf.push_back(11);

        Dns::BufferParser parser{std::span(buf)};
        auto name1 = parser.read_name();
        auto name2 = parser.read_name();
        auto name3 = parser.read_name();

        CHECK_EQ("abcde.xyz", name1);
        CHECK_EQ("abcde.xyz", name2);
        CHECK_EQ("abcde.xyz", name3);
    }

}

TEST_CASE("BufferParser dns_question")
{
    SUBCASE("single question")
    {
        std::vector<std::string> domain{"www", "coolio","com"};
        auto buf = generate_buffer_from_label_vec(domain);

        auto size_of_name = buf.size();
        //type
        buf.push_back(0b0000'0000);
        buf.push_back(0b0000'0001);
        //class
        buf.push_back(0b1000'0000);
        buf.push_back(0b0000'0001);

        Dns::BufferParser parser{std::span(buf)};
        auto question = parser.read_question();

        auto ref_name = std::accumulate(domain.begin(), domain.end(), std::string{}, [](auto sum, auto str)
        { return sum + str + ".";});
        ref_name.pop_back();
        uint16_t ref_type = static_cast<uint16_t>(buf[size_of_name]) << 8 | static_cast<uint16_t>(buf[size_of_name + 1]);
        uint16_t ref_class = static_cast<uint16_t>(buf[size_of_name + 2]) << 8 | static_cast<uint16_t>(buf[size_of_name + 3]);
        INFO("reference name: ", ref_name);
        INFO("parsed name: ", question.name);
        INFO("reference type: ", std::bitset<16>(ref_type));
        INFO("parsed type: ", std::bitset<16>(question.query_type));
        INFO("reference class: ", ref_class);
        INFO("parsed class: ", question.query_class);
        CHECK_EQ(question.name, ref_name);
        CHECK_EQ(question.query_type,  ref_type);
        CHECK_EQ(question.query_class, ref_class);

    }
}

TEST_CASE("BufferParser dns_answer")
{
    SUBCASE("single answer")
    {
        std::vector<std::string> domain{"www", "coolio","com"};
        auto buf = generate_buffer_from_label_vec(domain);
        auto size_of_name = buf.size();
        //type
        buf.push_back(0b0000'0000);
        buf.push_back(0b0000'0001);
        //class
        buf.push_back(0b1000'0000);
        buf.push_back(0b0000'0001);
        //ttl
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(0);
        buf.push_back(1);
        //len
        buf.push_back(0);
        buf.push_back(10);
        //ipv4
        buf.push_back(192);
        buf.push_back(168);
        buf.push_back(10);
        buf.push_back(1);

        Dns::BufferParser parser{std::span(buf)};
        auto answer = parser.read_answer();

        Dns::BufferParser ref_parser{std::span(buf)};

        auto ref_name = ref_parser.read_name();
        auto ref_type = Dns::get_query_type(ref_parser.read<uint16_t>());
        auto ref_class = ref_parser.read<uint16_t>();
        auto ref_ttl = ref_parser.read<uint32_t>();
        auto ref_len = ref_parser.read<uint16_t>();
        auto ref_ip4 = ref_parser.read<uint32_t>();

        CHECK_EQ(ref_name, answer.name);
        CHECK_EQ(ref_type, answer.query_type);
        CHECK_EQ(ref_class, answer.query_class);
        CHECK_EQ(ref_ttl, answer.ttl);
        CHECK_EQ(ref_len, answer.len);
        CHECK_EQ(ip::address_v4(ip::address_v4::uint_type(ref_ip4)).to_string(),
                 std::get<Dns::DnsAnswer::A>(answer.record).ip4Addr.to_string());
    }

}

TEST_CASE("getting answers from packet")
{
    SUBCASE("answer")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::DnsAnswer answer{"google.com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::A{15612}};
        packet.add_answer(std::move(answer));

        auto rng = packet.get_answers();
        CHECK_EQ(ip::udp::endpoint(ip::address_v4{15612},53), rng.front());
    }
    SUBCASE("unresolved")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::DnsAnswer answer{"google.com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::NS{"glabl.yam"}};
        packet.add_authority(std::move(answer));

        auto rng = packet.get_unresolved_ns("google.com");

        auto itt = ranges::find_if(rng, [](auto s) {return s == "google.com";});
        CHECK_EQ(rng.front(), std::get<Dns::DnsAnswer::NS>(packet.authorities.front().record).name);

    }

    SUBCASE("resolved")
    {
        auto packet = Dns::DnsPacket::generate(10, false, false);
        Dns::DnsAnswer answer{"ns.com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::A{15612}};
        packet.add_additional(std::move(answer));

        Dns::DnsAnswer auth{"com", static_cast<Dns::QueryType>(1), 1, 999, 10, Dns::DnsAnswer::NS{"ns.com"}};
        packet.add_authority(std::move(auth));

        auto rng = packet.get_resolved_ns("google.com");
        std::vector<ip::address_v4> vec{rng.begin(), rng.end()};
        CHECK_EQ(vec.size(), 1);
        CHECK_EQ(rng.front(), std::get<Dns::DnsAnswer::A>(packet.additionals.front().record).ip4Addr);

    }
}

std::array<uint8_t, DNS_BUF_SIZE> get_buf_from_file(const std::string& filename)
{
    char cbuf[DNS_BUF_SIZE];
    std::array<uint8_t, DNS_BUF_SIZE> buf{};
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    file.read(cbuf, DNS_BUF_SIZE);

    for (int i = 0; i < DNS_BUF_SIZE; i++)
        buf[i] = static_cast<uint8_t>(cbuf[i]);

    return buf;

}

