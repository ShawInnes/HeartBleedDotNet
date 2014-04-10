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
#if DEBUG
            string host = "10.0.1.2";
            int port = 5001;
#else
            if (args.Length == 0)
            {
                Usage();
                return;
            }

            string host = args[0];
            int port = 443;

            if (args.Length > 1 && !int.TryParse(args[1], out port))
                port = 443;
#endif

            SetupLogger();

            Processor processor = new Processor();
            Task<bool> task = Task.Run<bool>(() => processor.TestHost(host, port, SSLVersion.TLS1_2_VERSION));
            task.Wait();

            Console.ReadKey();
        }
    }
}
