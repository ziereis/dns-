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

        std::unique_ptr<DnsAnswer::Record> read_record(QueryType queryType);


        explicit BufferParser(std::span<uint8_t> buf_view);

        template<typename T>
        requires std::integral<T> || std::is_same_v<T, boost::multiprecision::uint128_t>
        T read();

        std::string read_name();
    private:


        template<typename T> requires std::integral<T>
        T get(size_t pos);

        void seek(size_t pos);


        std::span<uint8_t> buf_view;
        size_t position;
    };

}
