#pragma once
#include "DnsPacket.h"

namespace Dns
{

    template<typename T, typename Head, typename... Offsets>
    requires std::integral<T> && std::integral<Head>
    void set_bits_at_offsets(T& number, Head head, Offsets... offsets)
    {
        if (head >= sizeof(T) * 8)
            throw std::invalid_argument{"offset is out of bounds"};

        number |= (1 << head);

        if constexpr (sizeof...(Offsets) > 0)
        set_bits_at_offsets(number, offsets...);
    }

    template<typename T, typename Head, typename... Offsets>
    requires std::integral<T> && std::integral<Head>
    T get_bits_at_offsets(T number, Head head, Offsets... offsets)
    {
        T mask{0};
        set_bits_at_offsets(mask, head, offsets...);
        return number & mask;
    }

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
