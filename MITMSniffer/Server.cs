using System;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Collections.Generic;

namespace MITMSniffer {
	public class Server {
		/// <summary>
		/// What IP and Port to listen on.
		/// </summary>
		public IPEndPoint SourceEndPoint = new IPEndPoint(new IPAddress(0), 2008);
		/// <summary>
		/// Where to redirect the traffic after writing it down.
		/// </summary>
		public IPEndPoint TargetEndPoint = new IPEndPoint(new IPAddress(0), 2008);
		// Networking
		TcpListener listener;
		LinkedList<Client> clients = new LinkedList<Client>();
		// Threading
		Thread thread;
		ServerWorker threadWorker;

		public Server(IPAddress sourceAddress,
		              UInt16 sourcePort,
		              IPAddress targetAddress,
		              UInt16 targetPort) {
			// Update Source EndPoint and create socket.
			this.SourceEndPoint.Address = sourceAddress;
			this.SourceEndPoint.Port = sourcePort;
			this.listener = new TcpListener(this.SourceEndPoint);

			// Update Target EndPoint.
			this.TargetEndPoint.Address = targetAddress;
			this.TargetEndPoint.Port = targetPort;
		}

		/// <summary>
		/// Start the sniffing server.
		/// </summary>
		public void Start() {
			if (thread == null) {
				Console.Write("[{0}] Starting MITM-Sniffer...",
				              SourceEndPoint);

				threadWorker = new ServerWorker(this);
				thread = new Thread(threadWorker.DoWork);
				thread.Start();

				// Wait until Thread is alive.
				while (!thread.IsAlive)
					Thread.Sleep(1);

				Console.WriteLine("Done!");
			}
		}

		/// <summary>
		/// Stop the sniffing server.
		/// </summary>
		public void Stop() {
			if (thread != null) {
				threadWorker.ShouldStop = true;

				// Try to gracefully stop the server thread worker and thread.
				Console.Write("[{0}] Stopping MITM-Sniffer gracefully...",
				              SourceEndPoint);
				for (int i = 0; i < 10; i++) { // Wait one second for the server to shut down.
					if (!thread.IsAlive)
						break;
					Thread.Sleep(100);
				}

				// If graceful-stop failed, do a forceful-stop.
				if (thread.IsAlive) {
					Console.WriteLine("Failed!");
					Console.Write("[{0}] Stopping MITM-Sniffer forcefully...",
					              SourceEndPoint);
					thread.Abort();
					threadWorker.CleanUp();
				}
				Console.WriteLine("Done!");

				// Clear references
				threadWorker = null;
				thread = null;
			}
		}

		/// <summary>
		/// Internal class for threading.
		/// </summary>
		internal class ServerWorker {
			volatile bool shouldStop;
			Server server;

			/// <summary>
			/// Weether or not the worker should stop.
			/// </summary>
			/// <value><c>true</c> if should stop; otherwise, <c>false</c>.</value>
			public bool ShouldStop {
				get {
					return shouldStop;
				}
				set {
					shouldStop = value;
				}
			}

			/// <summary>
			/// Initializes a new instance of the <see cref="MITMSniffer.MITMServer+MITMServerWorker"/> class.
			/// </summary>
			/// <param name="server">Server.</param>
			public ServerWorker(Server server) {
				this.server = server;
			}

			/// <summary>
			/// Do the work.
			/// </summary>
			public void DoWork() {
				try {
					server.listener.Start();
					while (!ShouldStop) { // Continue until graceful stop is requested.
						// Accept new clients.
						while (server.listener.Pending()) {
							var tcpClient = server.listener.AcceptTcpClient();
							var client = new Client(server, tcpClient);
							client.Start();
							server.clients.AddLast(client);
						}

						// Ping MITMClients to check for dead threads (response time > 5000).
					}

					// Graceful stop.
					CleanUp();
					server.listener.Stop();
				} catch (Exception e) {
					Console.WriteLine(e);
					return;
				}
			}

			/// <summary>
			/// Cleans up.
			/// </summary>
			public void CleanUp() {
				if (server.clients.Count > 0) {
					foreach (Client c in server.clients)
						c.Stop();
					server.clients.Clear();
				}
			}
		}
	}
}

