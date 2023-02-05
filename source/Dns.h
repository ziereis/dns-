#pragma once


#include <boost/endian/buffers.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <array>
#include <span>
#include <iostream>
#include <utility>
#include <variant>

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
    struct __attribute__((packed)) DnsHeader
    {

        uint16_t id;

        uint8_t query_response :1;
        uint8_t op_code :4;
        uint8_t authoritative_answer :1;
        uint8_t truncated_message :1;
        uint8_t recursion_desired :1;

        uint8_t recursion_available :1;
        uint8_t reserved :3;
        uint8_t response_code :4;

        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t addtional_count;

        friend std::ostream &operator<<(std::ostream &os, const DnsHeader &header);
    };

    struct DnsQuestion
    {
        std::string name;
        uint16_t query_type;
        uint16_t query_class;

        friend std::ostream &operator<<(std::ostream &os, const DnsQuestion &question);
    };

    enum class QueryType{
        A = 1,
        NS = 2,
        CNAME = 5,
        MX = 15,
        AAA = 28,
        UNKNOWN = 678
    };

    Dns::QueryType  get_query_type(uint16_t query_num);

    struct DnsAnswer
    {
        struct Record
        {
            virtual ~Record()= default;
        };
        struct A : public Record
        {
            explicit A(uint32_t ip4Addr) : ip4Addr{ip4Addr}{};
            uint32_t ip4Addr;
        };

        struct NS : public Record
        {
            template<typename T>
            requires std::is_same_v<T,std::string>
            explicit NS(T&& name) : name{std::forward<T>(name)} {}
            std::string name;
        };

        struct CNAME : public Record
        {
            template<typename T>
            requires std::is_same_v<T,std::string>
            explicit CNAME(T&& name) : name{std::forward<T>(name)} {}
            std::string name;
        };

        struct MX : public Record
        {
            template<typename T>
            requires std::is_same_v<T,std::string>
            explicit MX(uint16_t priority, T&& name)
            : priority(priority)
            , name{std::forward<T>(name)} {}

            uint16_t priority;
            std::string name;
        };

        struct AAA: public Record
        {
            explicit AAA(boost::multiprecision::uint128_t&& ip6Addr) : ip6Addr{ip6Addr}{};
            uint32_t ip6Addr;
        };

        struct Unknown : public Record {};

        using DnsRecord = std::variant<A, NS, CNAME, MX, AAA,Unknown>;

        std::string name;
        QueryType query_type;
        uint16_t query_class;
        uint32_t ttl;
        uint16_t len;
        std::unique_ptr<Record> record;

        friend std::ostream &operator<<(std::ostream &os, const DnsAnswer &answer);
    };

    class DnsPacket
    {
    public:

        DnsPacket(std::array<uint8_t, DNS_BUF_SIZE>& buf, size_t bytes_read);

        Dns::DnsHeader header_;
        std::vector<DnsQuestion> questions;
        std::vector<DnsAnswer> answers;
        std::vector<DnsAnswer> authorities;
        std::vector<DnsAnswer> additionals;


    };

}
