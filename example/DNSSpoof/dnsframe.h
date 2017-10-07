#ifndef DNSFRAME_H
#define DNSFRAME_H

#include <pcapwrapper/helpers/common.h>

struct sniffdns_query {
    PCAP::uchar *m_query;
    PCAP::ushort m_type;
    PCAP::ushort m_class;
};

struct sniffdns_question {
    PCAP::ushort m_transation;
    PCAP::ushort m_flags;
    PCAP::ushort m_questions;
    PCAP::ushort m_answers;
    PCAP::ushort m_authority;
    PCAP::ushort m_additional;
};

struct sniffdns_answer {
    PCAP::ushort m_name;
    PCAP::ushort m_type;
    PCAP::ushort m_class;
    PCAP::uchar m_time_to_live[4];
    PCAP::ushort data_length;
    PCAP::uchar m_address[4];
};

#endif // DNSFRAME_H
