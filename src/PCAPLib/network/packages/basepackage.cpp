#include "basepackage.h"

#include <cstring>
#include <utility>

namespace PCAP {

BasePackage::BasePackage(const unsigned char *p, unsigned int l)
    : m_length{l} {
    memset(m_package, '\0', snap_len);
    memcpy(m_package, p, l);
}

BasePackage::BasePackage(const BasePackage& rhs)
    : m_length{rhs.m_length}
{
    memcpy(m_package, rhs.m_package, snap_len);
}

BasePackage& BasePackage::operator=(BasePackage rhs) {
    swap(*this, rhs);
    return *this;
}

BasePackage::BasePackage(BasePackage&& rhs) {
    swap(*this, rhs);
}

BasePackage& BasePackage::operator=(BasePackage&& rhs) {
    auto tmp = BasePackage(std::move(rhs));
    swap(*this, tmp);
    return *this;
}

void swap(BasePackage& lhs, BasePackage& rhs) {
    std::swap(lhs.m_length, rhs.m_length);
    std::swap(lhs.m_package, rhs.m_package);
}

BasePackage::~BasePackage() {
}

unsigned int BasePackage::getLength() const {
    return m_length;
}


}
