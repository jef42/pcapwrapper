#include "ipport.h"

std::ostream& operator<<(std::ostream& output, const IPPort& rhs) {
    output << "Time: " <<  std::put_time(std::localtime(&rhs.m_time), "%c %Z") << "IP: " << rhs.m_ip << " Src: "
           << rhs.m_src_port << " Dst: " << rhs.m_dst_port << std::endl;
    return output;
}
