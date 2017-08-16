#include "rawpackage.h"

#include <algorithm>

namespace PCAP {

RawPackage::RawPackage(const unsigned char *p, pcap_pkthdr header)
    : m_header{header}
    , m_raw{m_header.len ? new unsigned char[m_header.len]() : nullptr}
{
    std::copy(p, p + m_header.len, m_raw);
}

RawPackage::RawPackage(const RawPackage& rhs)
    : m_header{rhs.m_header}
    , m_raw{m_header.len ? new unsigned char[m_header.len]() : nullptr}
{
    std::copy(rhs.m_raw, rhs.m_raw + m_header.len, m_raw);
}

RawPackage& RawPackage::operator=(RawPackage rhs) {
    swap(*this, rhs);
    return *this;
}

RawPackage::RawPackage(RawPackage &&rhs)
    : m_header{rhs.m_header}
    , m_raw{nullptr}
{
    swap(*this, rhs);
}

RawPackage& RawPackage::operator=(RawPackage&& rhs) {
    swap(*this, rhs);
    delete[] rhs.m_raw;
    rhs.m_raw = nullptr;
    return *this;
}

RawPackage::~RawPackage() noexcept {
    delete[] m_raw;
}

void swap(RawPackage& first, RawPackage& rhs) {
    using std::swap;

    swap(first.m_header, rhs.m_header);
    swap(first.m_raw, rhs.m_raw);
}

}
