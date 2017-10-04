#include "../../../include/network/packages/basepackage.h"

#include <cstring>
#include <utility>

namespace PCAP {

BasePackage::BasePackage(const uchar *p, uint l, bool modify)
    : m_length{l}, m_modify{modify} {
    if (!m_modify) {
        m_package = const_cast<uchar *>(p);
    } else {
        m_package = new uchar[snap_len];
        memcpy(m_package, p, m_length);
    }
}

BasePackage::~BasePackage() {
    if (m_modify) {
        delete[] m_package;
    }
}

BasePackage::BasePackage(const BasePackage &rhs)
    : m_length{rhs.m_length}, m_modify{rhs.m_modify} {
    if (!m_modify) {
        m_package = rhs.m_package;
    } else {
        m_package = new uchar[snap_len];
        memcpy(m_package, rhs.m_package, m_length);
    }
}

BasePackage &BasePackage::operator=(BasePackage rhs) {
    swap(*this, rhs);
    return *this;
}

BasePackage::BasePackage(BasePackage &&rhs) noexcept { swap(*this, rhs); }

BasePackage &BasePackage::operator=(BasePackage &&rhs) noexcept {
    auto tmp = std::move(rhs);
    swap(*this, tmp);
    return *this;
}

void swap(BasePackage &lhs, BasePackage &rhs) noexcept {
    std::swap(lhs.m_length, rhs.m_length);
    std::swap(lhs.m_package, rhs.m_package);
    std::swap(lhs.m_modify, rhs.m_modify);
}

uint BasePackage::get_length() const { return m_length; }
}
