#pragma once


#include <boost/endian/buffers.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/asio.hpp>
#include <string>
#include <array>
#include <span>
#include <iostream>
#include <utility>
#include <variant>
#include <range/v3/all.hpp>

using namespace boost::asio;

#define ENABLE_DEBUG_LOG 1

#if ENABLE_DEBUG_LOG != 0
#define LOG(x) {std::cout << x << std::endl;}
#else
#define LOG(x)
#endif

using namespace boost::endian;

namespace
{
    constexpr uint16_t DNS_BUF_SIZE = 512;
}
namespace Dns
{
    namespace Flags
    {
        constexpr uint8_t QUERY_RESPONSE = 0b1000'0000;
        constexpr uint8_t OP_CODE = 0b0111'1000;
        constexpr uint8_t AUTHORITATIVE_ANSWER = 0b0000'0100;
        constexpr uint8_t TRUNCATED_MESSAGE = 0b0000'0010;
        constexpr uint8_t RECURSION_DESIRED = 0b0000'0001;

        constexpr uint8_t RECURSION_AVAILABLE = 0b1000'0000;
        constexpr uint8_t RESERVED = 0b0111'0000;
        constexpr uint8_t RESPONSE_CODE = 0b0000'1111;

    }

    enum class QueryType{
        A = 1,
        NS = 2,
        CNAME = 5,
        MX = 15,
        AAA = 28,
        UNKNOWN = 678
    };

    enum class ResponseCode {
        NOERROR = 0,
        FORMERR,
        SERVERFAIL,
        NXDOMAIN,
        NOTIMP,
        REFUSED
    };

    struct __attribute__((packed)) DnsHeader
    {
        uint16_t id;

        uint8_t flags1;
        uint8_t flags2;

        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t addtional_count;

        [[nodiscard]] bool get_query_response() const;
        [[nodiscard]] uint8_t get_op_code() const;
        [[nodiscard]] bool get_authoritative_answer() const;
        [[nodiscard]] bool get_truncated_message() const;
        [[nodiscard]] bool get_recursion_desired() const;

        [[nodiscard]] bool get_recursion_available() const;
        [[nodiscard]] uint8_t get_reserved() const;
        [[nodiscard]] uint8_t get_response_code() const;

        void set_recursion_desired(bool recursion_desired);
        void set_recursion_available(bool recursion_available);
        void set_reserved(uint8_t reserved);
        void set_query_response(bool response);

        static DnsHeader generate(uint16_t, bool response, bool recursion);


        friend std::ostream &operator<<(std::ostream &os, const DnsHeader &header);
    };

    struct DnsQuestion
    {
        std::string name;
        uint16_t query_type;
        uint16_t query_class;

        friend std::ostream &operator<<(std::ostream &os, const DnsQuestion &question);
    };


    Dns::QueryType  get_query_type(uint16_t query_num);

    struct DnsAnswer
    {
        struct A {
            explicit A(ip::address_v4::uint_type ip4Addr)
            : ip4Addr{ip4Addr} {}
            ip::address_v4 ip4Addr;
        };
        struct NS { std::string name;};
        struct CNAME { std::string name;};
        struct MX { uint16_t priority; std::string name;};
        struct AAA {
            explicit AAA(ip::address_v6::bytes_type ipv6Addr)
            : ip6Addr{ipv6Addr} {}
            ip::address_v6 ip6Addr;
        };
        struct Unknown {};

        using DnsRecord = std::variant<A, NS, CNAME, MX, AAA,Unknown>;

        DnsAnswer(std::string name, QueryType queryType, uint16_t query_class,
                  uint32_t ttl, uint16_t len, DnsRecord record);

        std::string name;
        QueryType query_type;
        uint16_t query_class;
        uint32_t ttl;
        uint16_t len;
        DnsRecord record;

        friend std::ostream &operator<<(std::ostream &os, const DnsAnswer &answer);
    };

    struct RecordPrintVisitor {
        void operator()(const DnsAnswer::A& record) const
        {
            std::cout << record.ip4Addr.to_string() << std::endl;
        }
        void operator()(const DnsAnswer::AAA& record) const
        {
            std::cout << record.ip6Addr.to_string() << std::endl;
        }
        void operator()(const DnsAnswer::Unknown& record) const
        {
            std::cout << "unknown" << std::endl;
        }
        void operator()(const auto& record) const
        {
            std::cout << record.name << std::endl;
        }
    };

    class DnsPacket
    {
    public:

        DnsPacket(const uint8_t* buf, std::size_t bytes_read);
        DnsPacket() = default;
        Dns::DnsHeader header_;
        std::vector<DnsQuestion> questions;
        std::vector<DnsAnswer> answers;
        std::vector<DnsAnswer> authorities;
        std::vector<DnsAnswer> additionals;

        static DnsPacket generate(uint16_t id, bool response, bool recursion);

        void add_question(DnsQuestion&& question);
        void add_answer(DnsAnswer&& answer);
        void add_authority(DnsAnswer&& authority);
        void add_additional(DnsAnswer&& answer);

        //have to implement here idk how to return a range
        auto get_unresolved_ns(std::string_view qname)const {
            auto ns_range = authorities
                   | ranges::views::filter([qname](auto& auth){
                return qname.ends_with(auth.name)
                       && std::get_if<Dns::DnsAnswer::NS>(&auth.record);
            })
                   | ranges::views::transform([](auto& authority){
                return std::get<Dns::DnsAnswer::NS>(authority.record).name;
            });
            return ns_range;
        }

        auto get_resolved_ns(std::string_view qname) const {
            auto ns_range = get_unresolved_ns(qname);
            for (auto a : ns_range)
            {
                std::cout << a << " ";
            }
            std::cout << std::endl;
            auto resolved_ns_ipv4 = additionals
                                    | ranges::views::filter([&ns_range](auto& additional){
                                        std::cout << additional.name << std::endl;
                                        return std::find_if(ns_range.begin(), ns_range.end(),[&additional](auto name){
                                            std::cout << additional.name << std::endl;
                                            std::cout << name << std::endl;
                                            return additional.name == name;
                                        }) != ns_range.end();
                                    })
                                    | ranges::views::filter([](auto& additional){
                                        return std::get_if<Dns::DnsAnswer::A>(&additional.record);
                                    })
                                    | ranges::views::transform([](auto& additional){
                                        return std::get<Dns::DnsAnswer::A>(additional.record).ip4Addr;
                                    });
            return resolved_ns_ipv4;
        }

        auto get_answers() const {
            auto eps = answers
                            | ranges::views::filter([](auto& answer) {
                return std::get_if<Dns::DnsAnswer::A>(&answer.record);
            })
                            | ranges::views::transform([](auto& answer){
                return ip::udp::endpoint(std::get<Dns::DnsAnswer::A>(answer.record).ip4Addr, 53);
            });
            return eps;
        }

        friend std::ostream &operator<<(std::ostream &os, const DnsPacket &packet);
    };

}
