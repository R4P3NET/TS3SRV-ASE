using System;
using System.Net.Sockets;
using System.Threading;

namespace MITMSniffer {
	public class Client {
		Server parentServer;
		TcpClient client;
		TcpClient targetClient;
		// Threading
		Thread thread;
		ClientWorker threadWorker;

		public Client (Server parentServer,
		               TcpClient client) {
			this.parentServer = parentServer;
			this.client = client;
			this.targetClient = new TcpClient ();
		}

		/// <summary>
		/// Start sniffing this client.
		/// </summary>
		public void Start () {
			if (thread == null) {
				Console.Write ("[{0}] Starting sniffer client for {1}...",
				               parentServer.SourceEndPoint,
				               client.Client.RemoteEndPoint);

				targetClient.Connect (parentServer.TargetEndPoint);
				threadWorker = new ClientWorker (this);
				thread = new Thread (threadWorker.DoWork);
				thread.Start ();

				// Wait until Thread is alive.
				while (!thread.IsAlive)
					Thread.Sleep (1);

				Console.WriteLine ("Done!");
			}
		}

		public void Stop () {
			if (thread != null) {
				threadWorker.ShouldStop = true;

				Console.Write ("[{0}] Stopping sniffer client for {1} gracefully...",
				               parentServer.SourceEndPoint,
				               client.Client.RemoteEndPoint);
				for (int i = 0; i < 10; i++) {
					if (threadWorker.IsStopped)
						break;
					Thread.Sleep (100);
				}
				if (!threadWorker.IsStopped) {
					Console.WriteLine ("Failed!");
					Console.WriteLine ("[{0}] Stopping sniffer client for {1} forcefully...",
						parentServer.SourceEndPoint,
						client.Client.RemoteEndPoint);
					thread.Abort ();
					threadWorker.CleanUp ();
				}
				Console.WriteLine ("Done!");

				// Clear references
				threadWorker = null;
				thread = null;
			}
		}

		internal class ClientWorker {
			// Control Booleans
			volatile bool _shouldStop;
			volatile bool _isStopped;
			Client client;

			/// <summary>
			/// Weether or not the worker should stop.
			/// </summary>
			/// <value><c>true</c> if should stop; otherwise, <c>false</c>.</value>
			public bool ShouldStop {
				get {
					return _shouldStop;
				}
				set {
					_shouldStop = value;
				}
			}

			/// <summary>
			/// Weether or not the worker has been gracefully stopped.
			/// </summary>
			/// <value><c>true</c> if this instance is stopped; otherwise, <c>false</c>.</value>
			public bool IsStopped {
				get {
					return _isStopped;
				}
				private set {
					_isStopped = value;
				}
			}

			public ClientWorker (Client client) {
				this.client = client;
			}

			/// <summary>
			/// Do the work.
			/// </summary>
			public void DoWork () {
				while (!ShouldStop) { // Continue until graceful stop is requested.
					while (client.client.Available > 0) {

					}


					// Check if client is still connected, otherwise break out.
					if (!client.client.Connected)
						break;

					Thread.Sleep (100);
				}

				// Graceful stop.
				CleanUp ();
				client.client.Close ();
				IsStopped = true;
			}

			/// <summary>
			/// Cleans up.
			/// </summary>
			public void CleanUp () {
				if (client.client.Connected)
					client.client.Close ();
			}
		}
	}
}

