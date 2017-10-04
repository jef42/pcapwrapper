#ifndef DNSFRAME_H
#define DNSFRAME_H

struct sniffdns_query {
    uchar *m_query;
    ushort m_type;
    ushort m_class;
};

struct sniffdns_question {
    ushort m_transation;
    ushort m_flags;
    ushort m_questions;
    ushort m_answers;
    ushort m_authority;
    ushort m_additional;
};

struct sniffdns_answer {
    ushort m_name;
    ushort m_type;
    ushort m_class;
    uchar m_time_to_live[4];
    ushort data_length;
    uchar m_address[4];
};

#endif // DNSFRAME_H
