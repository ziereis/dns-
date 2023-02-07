#pragma once
#include "DnsPacket.h"

namespace Dns
{
    class BufferParser
    {
public:
        DnsHeader read_header();
        DnsQuestion read_question();
        DnsAnswer read_answer();

        DnsAnswer::DnsRecord read_record(QueryType queryType);


        explicit BufferParser(std::span<const uint8_t> buf_view);

        template<typename T>
        requires std::integral<T> || std::is_same_v<T, boost::multiprecision::uint128_t>
        T read();

        template<typename T>
        requires std::integral<T> || std::is_same_v<T, boost::multiprecision::uint128_t>
        T get(size_t pos);

        std::string read_name();
    private:


        void seek(size_t pos);


        std::span<const uint8_t> buf_view;
        size_t position;
    };

}
