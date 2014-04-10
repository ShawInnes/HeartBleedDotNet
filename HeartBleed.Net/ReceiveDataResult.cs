using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.Net
{
    public class ReceiveDataResult
    {
        public bool Success { get; set; }
        public ushort Length { get; set; }
        public byte[] Buffer { get; set; }
    }
}
