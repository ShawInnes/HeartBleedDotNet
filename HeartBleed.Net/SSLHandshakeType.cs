using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.Net
{
    public enum SSLHandshakeType
    {
        SSL3_MT_HELLO_REQUEST = 0,
        SSL3_MT_CLIENT_HELLO = 1,
        SSL3_MT_SERVER_HELLO = 2,
        SSL3_MT_CERTIFICATE = 11,
        SSL3_MT_SERVER_KEY_EXCHANGE = 12,
        SSL3_MT_CERTIFICATE_REQUEST = 13,
        SSL3_MT_SERVER_DONE = 14,
        SSL3_MT_CERTIFICATE_VERIFY = 15,
        SSL3_MT_CLIENT_KEY_EXCHANGE = 16,
        SSL3_MT_FINISHED = 20,
    }
}
