//
// Created by thomas on 04.02.23.
//

#include <ostream>
#include "DnsPacket.h"
#include "BufferParser.h"

namespace Dns
{
    DnsPacket::DnsPacket(std::array<uint8_t, DNS_BUF_SIZE>& buf, size_t bytes_read)
    : header_{}, questions{}, answers{}, authorities{}, additionals{}
    {
        BufferParser parser{std::span(buf.data(), bytes_read)};
        header_ = parser.read_header();
        LOG(header_);

        for(size_t i = 0; i < header_.question_count; i++)
            questions.emplace_back(parser.read_question());

        for(size_t i = 0; i < header_.answer_count; i++)
            answers.emplace_back(parser.read_answer());

        for(size_t i = 0; i < header_.authority_count; i++)
            authorities.emplace_back(parser.read_answer());

        for(size_t i = 0; i < header_.addtional_count; i++)
            additionals.emplace_back(parser.read_answer());

#if ENABLE_DEBUG_LOG
        for(auto& q : questions)
            std::cout << q << std::endl;
        for(auto& q : answers)
            std::cout << q << std::endl;
        for(auto& q : authorities)
            std::cout << q << std::endl;
        for(auto& q : additionals)
            std::cout << q << std::endl;
#endif


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
           << "\n\tquery_response: " << std::to_string(header.query_response)
           << "\n\top_code: " << std::to_string(header.op_code)
           << "\n\tauthoritative_answer: " << std::to_string(header.authoritative_answer)
           << "\n\ttruncated_message: " << std::to_string(header.truncated_message)
           << "\n\trecursion_desired: " << std::to_string(header.recursion_desired)
           << "\n\trecursion_available: " << std::to_string(header.recursion_available)
           << "\n\treserved: " << std::to_string(header.reserved)
           << "\n\tresponse_code: " << std::to_string(header.response_code)
           << "\n\tquestion_count: " << header.question_count
           << "\n\tanswer_count: " << header.answer_count
           << "\n\tauthority_count: " << header.authority_count
           << "\n\taddtional_count: " << header.addtional_count << "}";
        return os;
    }
    std::ostream& operator<<(std::ostream &os, const DnsQuestion &question) {
        os << "name: " << question.name << " query_type: "
        << question.query_type << " query_class: "
        << question.query_class;
        return os;
    }


    std::ostream &operator<<(std::ostream &os, const DnsAnswer &answer) {
        os << "name: " << answer.name << " query_type: " << static_cast<uint16_t>(answer.query_type) << " query_class: " << answer.query_class
           << " ttl: " << answer.ttl << " len: " << answer.len << " record: " << answer.record;
        return os;
    }
}
