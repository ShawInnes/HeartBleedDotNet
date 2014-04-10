using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.Net
{
    public enum SSLHeaderType
    {
        SSL3_RT_CHANGE_CIPHER_SPEC = 20,
        SSL3_RT_ALERT = 21,
        SSL3_RT_HANDSHAKE = 22,
        SSL3_RT_APPLICATION_DATA = 23,
        SSL3_RT_HEARTBEAT = 24
    }
}
