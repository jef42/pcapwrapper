#ifndef BASEPACKAGE_H
#define BASEPACKAGE_H

#include "../../helpers/common.h"
#include "../../helpers/constants.h"

namespace PCAP {

class BasePackage {
  public:
    BasePackage(const uchar *p, uint l, bool modify = false);
    BasePackage(const BasePackage &rhs);
    BasePackage &operator=(const BasePackage rhs);
    BasePackage(BasePackage &&rhs) noexcept;
    BasePackage &operator=(BasePackage &&rhs) noexcept;

    friend void swap(BasePackage &lhs, BasePackage &rhs) noexcept;

    virtual const uchar *get_package() const { return m_package; }
    virtual uint get_length() const;

  protected:
    virtual ~BasePackage() noexcept;

    uchar *m_package;
    uint m_length;
    bool m_modify;
};
}

#endif // BASEPACKAGE_H
