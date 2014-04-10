using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.Net
{
    public class TestResult
    {
        public string Host { get; set; }
        public int Port { get; set; }
        public TimeSpan ElapsedTime { get; set; }
        public VulnerabilityStatus Status { get; set; }
        public byte[] Data { get; set; }
    }
}
