//
// Created by thomas on 04.02.23.
//

#include <ostream>
#include "Dns.h"
#include "BufferParser.h"

namespace Dns
{
    DnsPacket::DnsPacket(std::array<uint8_t, DNS_BUF_SIZE>& buf, size_t bytes_read)
    : header_{}
    {
        if (bytes_read < sizeof(header_))
            throw std::invalid_argument{"size of bytes read too small"};

        std::memcpy(&buf,&header_, sizeof(header_));

        BufferParser parser{std::span(buf).subspan(12)};

        std::cout << parser.read_question() << std::endl;
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

}
