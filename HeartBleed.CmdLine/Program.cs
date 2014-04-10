using HeartBleed.Net;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.CmdLine
{
    class Program
    {
        private static void Usage()
        {
            Console.WriteLine("Usage: <Command> <Hostname> [Port]");
            Console.WriteLine();
        }

        private static void SetupLogger()
        {
            Log.Logger = new LoggerConfiguration()
                    .WriteTo.Trace()
                    .WriteTo.ColoredConsole()
                    .CreateLogger();
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Usage();
                return;
            }

            string host = args[0];
            int port = 443;

            if (!int.TryParse(args[1], out port))
                port = 443;

            SetupLogger();

            Processor processor = new Processor();
            processor.TestHost(host, port);

            Console.ReadKey();
        }
    }
}
