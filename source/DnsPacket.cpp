//
// Created by thomas on 04.02.23.
//

#include <ostream>
#include <utility>
#include "DnsPacket.h"
#include "BufferParser.h"

namespace Dns
{
    DnsPacket::DnsPacket(const std::array<uint8_t, DNS_BUF_SIZE>& buf, size_t bytes_read)
    : header_{}, questions{}, answers{}, authorities{}, additionals{}
    {
        BufferParser parser{std::span(buf.data(), bytes_read)};
        header_ = parser.read_header();
        LOG(header_);

        for(size_t i = 0; i < header_.question_count; i++)
        {
            questions.emplace_back(parser.read_question());
            LOG(questions.back());
        }

        for(size_t i = 0; i < header_.answer_count; i++)
        {
            answers.emplace_back(parser.read_answer());
            LOG(answers.back());
        }

        for(size_t i = 0; i < header_.authority_count; i++)
        {
            authorities.emplace_back(parser.read_answer());
            LOG(authorities.back());
        }

        for(size_t i = 0; i < header_.addtional_count; i++)
        {
            additionals.emplace_back(parser.read_answer());
            LOG(additionals.back());
        }

    }

    DnsPacket DnsPacket::generate_default() {
        DnsPacket packet{};
        packet.header_ = DnsHeader::generate(1, false, true);
        packet.add_question("google.com", 1);
        return packet;
    }

    void DnsPacket::add_question(std::string name, uint16_t type) {
        ++header_.question_count;
        questions.emplace_back(DnsQuestion{std::move(name), type, 0});
    }


    QueryType  get_query_type(uint16_t query_num) {
        switch (query_num) {
            case static_cast<uint16_t>(QueryType::A):
                return QueryType::A;
            case static_cast<uint16_t>(QueryType::AAA):
                return QueryType::AAA;
            case static_cast<uint16_t>(QueryType::NS):
                return QueryType::NS;
            case static_cast<uint16_t>(QueryType::CNAME):
                return QueryType::CNAME;
            case static_cast<uint16_t>(QueryType::MX):
                return QueryType::MX;
            default:
                return QueryType::UNKNOWN;
        }
    }

    std::ostream& operator<<(std::ostream &os, const DnsHeader &header) {
        os << "DnsHeader{"
           << "\n\tid: " << header.id
           << "\n\tquery_response: " << header.get_query_response()
           << "\n\top_code: " << std::to_string(header.get_op_code())
           << "\n\tauthoritative_answer: " << header.get_authoritative_answer()
           << "\n\ttruncated_message: " << header.get_truncated_message()
           << "\n\trecursion_desired: " << header.get_recursion_desired()
           << "\n\trecursion_available: " << header.get_recursion_available()
           << "\n\treserved: " << std::to_string(header.get_reserved())
           << "\n\tresponse_code: " << std::to_string(header.get_response_code())
            << "\n\t flags1 =  :" << std::bitset<8>(header.flags1)
            << "\n\t flags2 =  :" << std::bitset<8>(header.flags2)
           << "\n\tquestion_count: " << header.question_count
           << "\n\tanswer_count: " << header.answer_count
           << "\n\tauthority_count: " << header.authority_count
           << "\n\taddtional_count: " << header.addtional_count << "}";
        return os;
    }


    bool DnsHeader::get_query_response() const {
        return (flags1 & Flags::QUERY_RESPONSE) >> 7;
    }

    uint8_t DnsHeader::get_op_code() const {
        return (flags1 & Flags::OP_CODE) >> 3;
    }

    bool DnsHeader::get_authoritative_answer() const {
        return (flags1 & Flags::AUTHORITATIVE_ANSWER) >> 2;
    }

    bool DnsHeader::get_truncated_message() const {
        return (flags1 & Flags::TRUNCATED_MESSAGE) >> 1;
    }

    bool DnsHeader::get_recursion_desired() const {
        return (flags1 & Flags::RECURSION_DESIRED) >> 0;
    }

    bool DnsHeader::get_recursion_available() const {
        return (flags2 & Flags::RECURSION_AVAILABLE) >> 7;
    }

    u_int8_t DnsHeader::get_reserved() const {
        return (flags2 & Flags::RESERVED) >> 4;
    }

    u_int8_t DnsHeader::get_response_code() const {
        return flags2 & Flags::RESPONSE_CODE;
    }

    void DnsHeader::set_recursion_desired(bool recursion_desired) {
        if (recursion_desired)
            flags1 |= Flags::RECURSION_DESIRED;
        else
            flags1 &= ~Flags::RECURSION_DESIRED;
    }

    void DnsHeader::set_recursion_available(bool recursion_available) {
        if (recursion_available)
            flags2 |= Flags::RECURSION_AVAILABLE;
        else
            flags2 &= ~Flags::RECURSION_AVAILABLE;

    }

    void DnsHeader::set_query_response(bool response) {
        if (response)
            flags2 |= Flags::QUERY_RESPONSE;
        else
            flags2 &= ~Flags::QUERY_RESPONSE;
    }

    DnsHeader DnsHeader::generate(uint16_t id, bool response, bool recursion) {
        DnsHeader header;
        header.id = id;
        header.flags1 = 0;
        header.flags2 = 0;
        header.set_query_response(response);
        header.set_recursion_desired(recursion);
        header.question_count = 0;
        header.answer_count = 0;
        header.addtional_count = 0;
        return header;
    }


    std::ostream& operator<<(std::ostream &os, const DnsQuestion &question) {
        os << "name: " << question.name << " query_type: "
        << question.query_type << " query_class: "
        << question.query_class;
        return os;
    }


    std::ostream &operator<<(std::ostream &os, const DnsAnswer &answer) {
        os << "name: " << answer.name << " query_type: " << static_cast<uint16_t>(answer.query_type) << " query_class: " << answer.query_class
           << " ttl: " << answer.ttl << " len: " << answer.len << " record: ";

        std::visit(RecordPrintVisitor{}, answer.record);
        return os;
    }

    DnsAnswer::DnsAnswer(std::string name, QueryType queryType, uint16_t query_class,
                         uint32_t ttl, uint16_t len, DnsRecord record)
                         : name{std::move(name)}
                         , query_type{queryType}
                         , query_class{query_class}
                         , ttl{ttl}
                         , len{len}
                         , record{std::move(record)}
                         {}
}
