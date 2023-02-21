#include <stdexcept>
#include "BufferParser.h"
#include <range/v3/all.hpp>



namespace
{
    constexpr uint8_t JUMP_MASK = 0b1100'0000;
    constexpr uint16_t JUMP_MASK_16 = 0b0011'1111'1111'1111;
    constexpr uint8_t MAX_JUMPS = 5;
    constexpr uint8_t FLAG_SIZE = 2;
}
namespace Dns
{
    DnsHeader BufferParser::read_header() {
        DnsHeader header{};
        if (buf_view.size() < sizeof(header))
            throw std::invalid_argument{"size of bytes read too small"};
        header.id = read<uint16_t>();
        header.flags1 = read<uint8_t>();
        header.flags2 = read<uint8_t>();

        header.question_count = read<uint16_t>();
        header.answer_count = read<uint16_t>();
        header.authority_count = read<uint16_t>();
        header.addtional_count = read<uint16_t>();
        return header;
    }

    DnsQuestion BufferParser::read_question(){
        return {read_name(),read<uint16_t>(), read<uint16_t>()};
    }

    DnsAnswer BufferParser::read_answer(){
        auto name = read_name();
        auto query_type = get_query_type(read<uint16_t>());
        auto query_class = read<uint16_t>();
        auto ttl = read<uint32_t>();
        auto len = read<uint16_t>();
        auto record  = read_record(query_type);
        return {name, query_type, query_class, ttl,
                len, std::move(record)};
    }
    DnsAnswer::DnsRecord BufferParser::read_record(QueryType query_type){
        switch (query_type) {
            case QueryType::A:
                return DnsAnswer::A{read<uint32_t>()};
            case QueryType::AAA:
                return DnsAnswer::AAA{read_ipv6()};
            case QueryType::NS:
                return DnsAnswer::NS{read_name()};
            case QueryType::CNAME:
                return DnsAnswer::CNAME{read_name()};
            case QueryType::MX:
                return DnsAnswer::MX{read<uint16_t>(), read_name()};
            default:
                return DnsAnswer::Unknown{};
        }
    }



    std::string BufferParser::read_name()  {
        std::string name;
        auto local_pos = position;

        int jump_counter{0};
        while(true) {
            if (jump_counter > MAX_JUMPS)
                throw std::invalid_argument{"max amount of jumps reached"};

            auto len = get<uint8_t>(local_pos);

            if ((JUMP_MASK & len) == JUMP_MASK) {
                if (!jump_counter)
                    seek(local_pos + 2);

                auto offset = get<uint16_t>(local_pos) & ~(static_cast<uint16_t>(JUMP_MASK) << 8);
                local_pos = static_cast<size_t>(offset);

                jump_counter++;
                continue;
            }
            else
            {
                ++local_pos;

                if (!len) break;


                auto end = local_pos + len;
                for (std::size_t i = local_pos; i < end; ++i)
                {
                    name += static_cast<char>(get<uint8_t>(i));
                }
                name += ".";

                local_pos += len;
            }

        }
        if (!jump_counter) {
            seek(local_pos);
        }
        if (!name.empty())
            name.pop_back();
        return name;
    }

        template<typename T>
        requires std::integral<T>
        T BufferParser::read()
        {
            T result = get<T>(position);
            position+= sizeof(T);
            return result;
        }


        template<typename T>
        requires std::integral<T>
        T BufferParser::get(size_t pos) const
        {
            if (pos + sizeof(T)> buf_view.size())
                throw std::invalid_argument{"trying to get position outside of the Buffer"};

            T result{0};
            for (int i = sizeof(T) -1; i >= 0; i--)
            {
                result |= (static_cast<T>(buf_view[pos]) << (8*i));
                ++pos;
            }
            return result;
        }

        ip::address_v6::bytes_type BufferParser::read_ipv6()
        {
            ip::address_v6::bytes_type result{};

            if (position + result.size() > buf_view.size())
                throw std::invalid_argument{"trying to get position outside of the Buffer"};

            for (unsigned char& i : result)
            {
                i = buf_view[position];
                ++position;
            }
            return result;
        }

        void BufferParser::seek(size_t pos)
        {
            position = pos;
        }

         BufferParser::BufferParser(std::span<const uint8_t> buf_view)
                : buf_view{buf_view}
                , position{0}
        {}

    // for tests
    template uint8_t BufferParser::read<uint8_t>();
    template uint16_t BufferParser::read<uint16_t>();
    template uint32_t BufferParser::read<uint32_t>();

    template<typename T>
    requires std::integral<T> || std::is_same_v<T, std::byte>
    void BufferBuilder::write(T bytes) {
        if (position + sizeof(T) > buf.size())
            throw std::invalid_argument{"trying to write position outside of the Buffer"};

        for (int i = sizeof(T) -1; i >= 0; i--)
        {
            buf[position] = static_cast<uint8_t>(bytes >> (8*i));
            ++position;
        }
    }

    // for tests
    template void BufferBuilder::write<uint8_t>(uint8_t);
    template void BufferBuilder::write<uint16_t>(uint16_t);
    template void BufferBuilder::write<uint32_t>(uint32_t);

    void BufferBuilder::write_header(const DnsHeader &header) {
        write(header.id);
        write(header.flags1);
        write(header.flags2);
        write(header.question_count);
        write(header.answer_count);
        write(header.authority_count);
        write(header.addtional_count);
    }

    void BufferBuilder::write_name(const std::string& name) {
        auto rng = name
                   | ranges::view::split('.')
                   | ranges::view::transform([](auto&& rng) {
            return std::string_view(&*rng.begin(), ranges::distance(rng));
        });
        for (auto label : rng){
            write<uint8_t>(label.size());
            for (auto& c : label)
                write<std::byte>(std::byte(c));
        }
        write<uint8_t>(0);
    }

    void BufferBuilder::write_question(const DnsQuestion &question) {
        write_name(question.name);
        write<uint16_t>(question.query_type);
        write<uint16_t>(question.query_class);
    }

    void BufferBuilder::buildPacket() {
        std::array<uint8_t, DNS_BUF_SIZE> buf{};
        write_header(packet.header_);
        for (auto & q : packet.questions)
            write_question(q);
    }

    std::span<uint8_t> BufferBuilder::get_buf() {
        return {buf.data(), position};
    }

    std::span<uint8_t> BufferBuilder::build_and_get_buf() {
        buildPacket();
        return get_buf();
    }

    BufferBuilder::BufferBuilder(const DnsPacket &packet)
    : position{0}
    , packet{packet}
    , buf{}
    {}


}
