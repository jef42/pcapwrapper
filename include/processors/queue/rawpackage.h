#ifndef RAWPACKAGE_H
#define RAWPACKAGE_H

#include "pcap.h"

namespace PCAP {

class RawPackage {
public:
    RawPackage(const unsigned char *p, pcap_pkthdr header);
    RawPackage(const RawPackage& rhs);
    RawPackage& operator=(RawPackage rhs);
    RawPackage(RawPackage &&rhs);
    RawPackage& operator=(RawPackage&& rhs);
    ~RawPackage() noexcept;

    friend void swap(RawPackage& first, RawPackage& rhs) noexcept;

    unsigned char* raw() const {
        return m_raw;
    }

    pcap_pkthdr header() const {
        return m_header;
    }

private:
    pcap_pkthdr m_header;
    unsigned char* m_raw;
};

}


#endif // RAWPACKAGE_H
