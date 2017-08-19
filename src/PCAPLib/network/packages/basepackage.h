#ifndef BASEPACKAGE_H
#define BASEPACKAGE_H

#include "../../helpers/constants.h"

namespace PCAP {

class BasePackage {
  public:
    BasePackage(const unsigned char* p, unsigned int l);

    BasePackage(const BasePackage& rhs);
    BasePackage& operator=(const BasePackage rhs);
    BasePackage(BasePackage&& rhs) noexcept;
    BasePackage& operator=(BasePackage&& rhs) noexcept;

    friend void swap(BasePackage& lhs, BasePackage& rhs) noexcept;

    virtual const unsigned char* getPackage() const {
        return m_package;
    }
    virtual unsigned int getLength() const;
  protected:
    virtual ~BasePackage() noexcept = default;

    unsigned char m_package[snap_len];
    unsigned int m_length;
};

}

#endif // BASEPACKAGE_H
