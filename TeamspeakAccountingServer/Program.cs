using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Threading;
using System.Net;
using System.Diagnostics;
using System.Collections;
using System.Runtime.Remoting.Lifetime;
using System.Runtime.Remoting.Messaging;
using System.IO;
using System.Text;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace TeamspeakAccountingServer {
    class MainClass {
        /* http://lapo.it/asn1js/#30819E03020780020130023034D55413D88BCF8D097596F6ED24C949361C5E1D82513527FF1B903A1CEF72CF22E941FCF5D03446A9CF9BC70E0266DA023100AEB8D0F5AE847E8A03FC4875945763F96F7335889F1A54854D44376DA7D0C2F250D1DE5A8FEF7E478B6B46131F4AFBA10230707A756D527B069294B4B581C9B960A8877DA5FCF943B3C45B2250CCDD81AD419D71A026465D8494F252F51257861FBD
            Private Key: Yes
            Key Size: 48
            Pub Curve x:  8131791298239097088373381674190843694597541613694669308313503149484081030264706701136842308922120197562173539641050
            Pub Curve y: 26892167587170708307087167633827033471383350498483121922850054644593608962451732627867862518607341888532511573343137
            Key Scalar:  17312003175271124858318089123719955952391833140105863084737889839320526623930200082521141732248589389333314255855549
        */
        static Boolean doShutDown = false;

        public static Int32 Main(string[] args) {
            Console.CancelKeyPress += new ConsoleCancelEventHandler(MainClass.ConsoleShutdown);

            Server myServer = new Server();
            try {
                myServer.Start();
                do {
                    myServer.Update();
                    Thread.Sleep(10);
                    if (MainClass.doShutDown == true)
                        break;
                } while (true);

                myServer.Stop();
                return 0;
            } catch (Exception e) {
                Console.ForegroundColor = ConsoleColor.DarkRed;
                Console.BackgroundColor = ConsoleColor.Gray;
                Console.WriteLine(e);
                Console.ReadKey();
                return -1;
            }

            using (var ec = new ECDiffieHellmanCng(eccKey)) {
                var message = "Hello World!";
                Console.WriteLine("Real Message: ");
                Console.WriteLine(message);
            }
        }

        protected static void ConsoleShutdown(object sender,
                                              ConsoleCancelEventArgs args) {
            MainClass.doShutDown = true;
        }

        /// <summary>
        /// Print a nice visual of the Buffer starting at offset.
        /// </summary>
        /// <param name="buffer">Buffer.</param>
        /// <param name="Offset">Offset.</param>
        public static void PrintHEX(Byte[] buffer,
                                    int Offset = 0) {
            Console.WriteLine(" 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F | Text    ");
            Console.WriteLine("------------------------------------------------|---------");
            int count = 0, cur = 0;
            String left = "", right = "";
            foreach (byte b in buffer) {
                if (cur >= Offset) {
                    if (count >= 16) {
                        Console.WriteLine("{0}| {1}", left, right);

                        left = "";
                        right = "";
                        count = 0;
                    }

                    left += String.Format("{0:x2} ", b);
                    if (b >= 32 && b <= 255)
                        right += (char)b;
                    else
                        right += ".";

                    count++;
                } else
                    cur++;
            }

            if (count > 0)
                Console.WriteLine("{0}| {1}", left.PadRight(48), right);
        }

        public static CngKey eccKey { get; set; }
    }

    internal class Server {
        // User Settings
        private UInt16 port = 2008;
        // Private ECC Key
        private CngKey m_PrivateKey = CngKeyConverter.Import(System.IO.File.ReadAllBytes("PrivateKey.ecc"));
        // Networking Stuff
        private TcpListener m_server = null;
        private LinkedList<Client> m_clientList = new LinkedList<Client>();

        /// <summary>
        /// Initializes a new instance of the <see cref="TeamspeakAccountingServer.Server"/> class.
        /// </summary>
        /// <param name="hostPort">Host port.</param>
        public Server(UInt16 hostPort = 2008) {
            this.port = hostPort;
        }

        /// <summary>
        /// Start this instance.
        /// </summary>
        public void Start() {
            if (this.m_server == null) {
                Console.WriteLine("[Server->Start] Starting server.");
                this.m_clientList.Clear();
                this.m_server = new TcpListener(IPAddress.Any, this.port);
                this.m_server.Start();
                Console.WriteLine("[Server->Start] Started server.");
            } else {
                throw new InvalidOperationException("Server is already running!");
            }
        }

        /// <summary>
        /// Stop this instance
        /// </summary>
        public void Stop() {
            if (this.m_server != null) {
                Console.WriteLine("[Server->Start] Stopping server...");
                // Stop client work and terminate sockets.
                foreach (Client client in m_clientList) {
                    client.Stop();
                }
                this.m_clientList.Clear();

                // Terminate server.
                this.m_server.Stop();
                this.m_server = null;
                Console.WriteLine("[Server->Start] Stopped server.");
            } else {
                throw new InvalidOperationException("Server is not running!");
            }
        }

        /// <summary>
        /// Update this instance.
        /// </summary>
        public void Update() {
            if (this.m_server != null) {
                while (this.m_server.Pending()) {
                    Console.WriteLine("[Server->Update] New client connecting.");

                    Client client = new Client(this, this.m_server.AcceptTcpClient());
                    this.m_clientList.AddLast(client);
                    client.Start();
                }

                LinkedList<Client> clientStopped = new LinkedList<Client>();
                foreach (Client client in this.m_clientList) {
                    if (client.Update()) {
                        clientStopped.AddLast(client);
                        client.Stop();
                    }
                }
                foreach (Client client in clientStopped) {
                    this.m_clientList.Remove(client);
                }
            } else {
                throw new InvalidOperationException("Server is not running!");
            }
        }

        /// <summary>
        /// Retrieves the Private Key this Server uses.
        /// </summary>
        /// <returns>The key.</returns>
        public CngKey GetKey() {
            return this.m_PrivateKey;
        }
    }

    internal class Client {
        private Server server;
        private TcpClient client;
        private ClientState clientState = ClientState.HandshakeConnect;
        private ECDiffieHellmanCng cngECC;
        private CngKey cngOtherKey;
        private Byte[] cngKeyMaterial, rsaSecretKey = new Byte[64];
        // Cipher
        private Org.BouncyCastle.Crypto.IBufferedCipher cipher;
        private int cipherIV;

        public Client(Server parent,
                      TcpClient client) {
            this.server = parent;
            this.client = client;
            this.cngECC = new ECDiffieHellmanCng(parent.GetKey());
            (new System.Random()).NextBytes(this.rsaSecretKey);
            this.cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        }

        /// <summary>
        /// Start this instance.
        /// </summary>
        public void Start() {
            if (this.client != null) {
                if (!this.client.Connected) {
                    this.Stop();
                }
            }
        }

        /// <summary>
        /// Stop this instance.
        /// </summary>
        public void Stop() {
            if (this.client != null) {
                if (this.cngECC != null) {
                    this.cngECC.Clear();
                    this.cngECC = null;
                }

                this.client.Close();
                this.client = null;
            }
        }

        /// <summary>
        /// Update this instance.
        /// </summary>
        /// <returns>Weether or not this instane is done updating.</returns>
        public Boolean Update() {
            if (this.client != null && this.client.Connected) {
                switch (clientState) {
                    case ClientState.HandshakeConnect:
                        if (this.client.Available > 0) {
                            Byte[] header = new Byte[4];
                            this.client.GetStream().Read(header, 0, 4);

                            var stringHeader = System.Text.ASCIIEncoding.ASCII.GetString(header);

                            if (stringHeader == "TS3C") {
                                this.clientState = ClientState.HandshakePublicKey;

                                Console.WriteLine("[Client->Update] ({0}) Accepted new client into list.",
                                                  this.client.Client.RemoteEndPoint.ToString());
                            } else {
                                Console.WriteLine("[Client->Update] ({0}) Not a license request, disconnecting.",
                                                  this.client.Client.RemoteEndPoint.ToString());
                                return true;
                            }
                        }
                        break;
                    case ClientState.HandshakePublicKey:
                        if (this.client.Available > 0) {
                            Console.WriteLine("[Client->Update] ({0}) Trying to read clients public key...",
                                              this.client.Client.RemoteEndPoint.ToString());

                            // Read Packet
                            Byte[] buffer = new Byte[this.client.Available];
                            Int32 dataLength = this.client.GetStream().Read(buffer, 0, this.client.Available);
                            try {
                                // The clients key starts at 7 bytes into the message, so we ignore the previous ones.
                                this.cngOtherKey = CngKeyConverter.Import(buffer, 7);
                                this.cngKeyMaterial = cngECC.DeriveKeyMaterial(this.cngOtherKey);

                                Console.WriteLine("[Client->Update] ({0}) Successfully read public key.",
                                                  this.client.Client.RemoteEndPoint.ToString());
                                this.clientState = ClientState.HandshakeInitiateRSA;
                            } catch (Exception e) {
                                Console.WriteLine("[Client->Update] ({0}) Failed to read public key from client:",
                                                  this.client.Client.RemoteEndPoint.ToString());
                                Console.WriteLine(e);
                                return true;
                            }
                        }

                        break;
                    case ClientState.HandshakeInitiateRSA:
                        try {
                            Console.WriteLine("[Client->Update] ({0}) Building and sending response...",
                                              this.client.Client.RemoteEndPoint.ToString());

                            // Create basic packet construct.
                            Int32 constructLength = 73;
                            Byte[] construct = new Byte[]{
								// Length of Packet
								(Byte)(constructLength & 0xFF), (Byte)((constructLength >> 8) & 0xFF), (Byte)((constructLength >> 16) & 0xFF), (Byte)((constructLength >> 24) & 0xFF),
								// Actual Packet
								0x54, 0x53, 0x33, 0x41, // TS3A (Header)
								0x04, 0x00, 0x00, 0x00, // .... (What is this?) (Packet Type?)
								// RSA Secret Key
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								// Null Termination
								0x00
							};
                            Array.Copy(this.rsaSecretKey, 0, construct, 12, 64);

                            // Encrypt packet for Teamspeak.
                            Byte[] packet = new Byte[construct.Length];
                            cipher.Init(true,
                                        new ParametersWithIV(new KeyParameter(this.cngKeyMaterial),
                                                             new Byte[64],
                                                             0,
                                                             64));
                            cipher.ProcessBytes(construct, 0, 4, packet, 0);
                            //cipher.DoFinal(construct, 4, constructLength, packet, 4);
                            //Array.Copy(construct, packet, 4);
                            
                            //MainClass.PrintHEX(packet);

                            // Send packet
                            this.client.GetStream().Write(packet,
                                                          0,
                                                          packet.Length);
                            this.client.GetStream().Flush();
                            this.clientState = ClientState.ReadLicenseDataHeader;
                        } catch (Exception e) {
                            Console.WriteLine(e);
                            return true;
                        }
                        break;
                    case ClientState.ReadLicenseDataHeader:
                        if (this.client.Available > 0)
                            Console.WriteLine("[Client->Update] ({0}) Available Data: {1}.",
                                              this.client.Client.RemoteEndPoint.ToString(),
                                              this.client.Available);

                        break;
                    case ClientState.ReadLicenseData:

                    default:
                        return true;
                }
                return false;
            } else
                return true;
        }

        internal enum ClientState {
            HandshakeConnect,
            HandshakePublicKey,
            HandshakeInitiateRSA,
            ReadLicenseDataHeader,
            ReadLicenseData,
            RespondVServer,
            RespondServer,
        }
    }
}