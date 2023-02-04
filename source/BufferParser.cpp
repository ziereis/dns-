#include <stdexcept>
#include "BufferParser.h"


namespace
{
    constexpr uint8_t JUMP_MASK = 0b1100'0000;
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
        std::memcpy(buf_view.data() + sizeof(uint16_t), &header, FLAG_SIZE);
        seek(position + FLAG_SIZE);

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
        auto query_type = static_cast<Dns::QueryType>(read<uint16_t>());
        return {name, query_type, read<uint16_t>(), read<uint32_t>(),
                read<uint16_t>(), read_record(query_type)};
    }

    DnsAnswer::DnsRecord BufferParser::read_record(QueryType query_type){
        switch (query_type) {
            case QueryType::A:
                return DnsAnswer::A{read<uint32_t>()};
            case QueryType::AAA:
                return DnsAnswer::AAA{read<boost::multiprecision::uint128_t>()};
            case QueryType::NS:
                return DnsAnswer::NS{read_name()};
            case QueryType::CNAME:
                return DnsAnswer::CNAME{read_name()};
            case QueryType::MX:
                return DnsAnswer::MX{read<uint16_t>(), read_name()};
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
            if (!len) break;

            if ((JUMP_MASK & len) == JUMP_MASK) {
                LOG("jumped");
                if (!jump_counter)
                    seek(position + 2);

                jump_counter++;
                auto offset = get<uint16_t>(local_pos) & ~(static_cast<uint16_t>(JUMP_MASK) << 8);

                local_pos += static_cast<size_t>(offset);
                continue;
            }
            else
            {
                auto end = local_pos + len;
                for (++local_pos; local_pos <= end; ++local_pos)
                {
                    name += static_cast<char>(get<uint8_t>(local_pos));
                }
                name += ".";
            }

        }
        if (!jump_counter) {
            seek(local_pos+1);
        }
        name.pop_back();
        return name;
    }

        template<typename T>
        requires std::integral<T> || std::is_same_v<T, boost::multiprecision::uint128_t>
        T BufferParser::read()
        {
            if (position + sizeof(T) > buf_view.size())
                throw std::invalid_argument{"trying to get position outside of the Buffer"};

            T result{0};
            for (size_t i = 0; i < sizeof(T); ++i)
            {
                result = result << 8 | static_cast<T>(buf_view[position]);
                ++position;
            }

            return result;
        }

        template<typename T> requires std::integral<T>
        T BufferParser::get(size_t pos)
        {
            if (pos + sizeof(T)> buf_view.size())
                throw std::invalid_argument{"trying to get position outside of the Buffer"};

            T result{0};
            for (size_t i = 0; i < sizeof(T); ++i)
            {
                result = result << 8 | static_cast<T>(buf_view[pos]);
                ++pos;
            }
            return result;
        }

        void BufferParser::seek(size_t pos)
        {
            if (pos >= buf_view.size())
                throw std::invalid_argument{"trying to get position outside of the Buffer"};
            position = pos;

        }

         BufferParser::BufferParser(std::span<uint8_t> buf_view)
                : buf_view{buf_view}
                , position{0}
        {}

    // for tests
    template uint8_t BufferParser::read<uint8_t>();
    template uint16_t BufferParser::read<uint16_t>();
    template uint32_t BufferParser::read<uint32_t>();
}
