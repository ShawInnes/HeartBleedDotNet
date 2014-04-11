using HeartBleed.Net;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.CmdLine
{
    class Program
    {
        private static void Usage()
        {
            string file = Assembly.GetExecutingAssembly().Location;
            string app = System.IO.Path.GetFileName(file);

            Console.WriteLine("Usage: {0} <Hostname> [Port]", app);
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

            if (args.Length > 1 && !int.TryParse(args[1], out port))
                port = 443;

            SetupLogger();

            Processor processor = new Processor();

            //string file = @"c:\jobs\vuln.txt";
            //if (System.IO.File.Exists(file))
            //{
            //    string[] readAllLines = System.IO.File.ReadAllLines(file);
            //    int port = 443;

            //    foreach (string host in readAllLines.OrderBy(p => p))
            //    {
            Log.Information("Processing Host {Host}", host);

            Task<TestResult> task = Task.Run<TestResult>(() => processor.TestHost(host, port, SSLVersion.SSL3_0_VERSION));
            task.Wait();

            Log.Information("Task Completed in {ElapsedTime}, {Host}, {Port}, {Status} {@Result}", task.Result.ElapsedTime, task.Result.Host, task.Result.Port, task.Result.Status, task.Result);

            if (task.Result.Data != null)
                Log.Information("Data for {Host} {Data}", task.Result.Host, task.Result.Data.Select(p => (int)p));

            System.Threading.Thread.Sleep(3000);
            //    }
            //}
        }
    }
}
