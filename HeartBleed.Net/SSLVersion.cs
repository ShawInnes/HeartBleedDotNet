using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.Net
{
    public enum SSLVersion
    {
        SSL3_0_VERSION = 0x0300,
        TLS1_0_VERSION = 0x0301,
        TLS1_1_VERSION = 0x0302,
        TLS1_2_VERSION = 0x0303,
    }
}
