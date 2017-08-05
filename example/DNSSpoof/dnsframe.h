#ifndef DNSFRAME_H
#define DNSFRAME_H

struct sniffdns_query {
    unsigned char* m_query;
    unsigned short m_type;
    unsigned short m_class;
};

struct sniffdns_question {
    unsigned short m_transation;
    unsigned short m_flags;
    unsigned short m_questions;
    unsigned short m_answers;
    unsigned short m_authority;
    unsigned short m_additional;
};

struct sniffdns_answer {
    unsigned short m_name;
    unsigned short m_type;
    unsigned short m_class;
    unsigned char m_time_to_live[4];
    unsigned short data_length;
    unsigned char m_address[4];
};

#endif // DNSFRAME_H
