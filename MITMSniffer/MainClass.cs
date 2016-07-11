using System;
using System.Net;
using System.Threading;

namespace MITMSniffer {
	class MainClass {
		public static void Main(string[] args) {
			var myServer = new Server(IPAddress.Parse("127.0.0.1"),
			                             25025,
			                             IPAddress.Any,
			                             2008);

			myServer.Start();
			do {
				Thread.Sleep(1);
			} while(Console.ReadLine() != "exit");
			myServer.Stop();

			Console.WriteLine("Press any key to continue.");
			Console.ReadKey();
		}
	}
}
