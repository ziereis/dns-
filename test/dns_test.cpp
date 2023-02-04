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
        std::array<uint8_t,2> buf{0b0101'1101};
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
TEST_CASE("BufferParser read_name")
{
    SUBCASE("single_name")
    {
        std::vector<std::string> domain{"www", "coolio","com"};
        auto buf = generate_buffer_from_label_vec(domain);
        // has to be 1 bigger to not throw exception at seek
        buf.push_back(0);
        Dns::BufferParser parser{std::span(buf)};
        auto name = parser.read_name();
        auto ref_name = std::accumulate(domain.begin(), domain.end(), std::string{}, [](auto sum, auto str)
            { return sum + str + ".";});
        ref_name.pop_back();
        INFO("reference Value: ", ref_name);
        INFO("parsed Value: ", name);
        CHECK((name == ref_name));
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
        INFO("reference type: ", ref_type);
        INFO("parsed type: ", question.query_type);
        INFO("reference class: ", ref_class);
        INFO("parsed class: ", question.query_class);
        CHECK((question.name == ref_name));
        CHECK((question.query_type == ref_type));
        CHECK((question.query_class == ref_class));

    }
}

TEST_CASE("BufferParser dns_question")
{
    SUBCASE("single question")
    {

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

