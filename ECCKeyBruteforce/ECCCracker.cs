using System;
using System.Threading;
using System.Security.Cryptography;
using System.Numerics;
using System.IO;
using Community.CsharpSqlite.SQLiteClient;
using System.Data.Common;
using System.Data.SqlClient;
using System.Data;
using Community.CsharpSqlite;
using System.Diagnostics;

namespace ECCKeyBruteforce {
	class ECCCracker {
		public String StoragePath = "C:\\Public\\ECC";
		public String StorageKeyPath;
		public String StorageDatabasePath;

		#region Database

		const String TABLETHREADSNAME = "threads";
		const String TABLETHREADS = "CREATE TABLE IF NOT EXISTS {0} (" +
		                            "Id INTEGER NOT NULL PRIMARY KEY," +
		                            "Id0 INTEGER NOT NULL," +
		                            "Id1 INTEGER NOT NULL," +
		                            "Id2 INTEGER NOT NULL," +
		                            "Id3 INTEGER NOT NULL," +
		                            "Id4 INTEGER NOT NULL," +
		                            "Id5 INTEGER NOT NULL," +
		                            "UNIQUE(Id0,Id1,Id2,Id3,Id4,Id5)" +
		                            ");";
		const String TABLEBLOCKSNAME = "blocks";
		const String TABLEBLOCKS = "CREATE TABLE IF NOT EXISTS {0} (" +
		                           "Id0 INTEGER NOT NULL," +
		                           "Id1 INTEGER NOT NULL," +
		                           "Id2 INTEGER NOT NULL," +
		                           "Id3 INTEGER NOT NULL," +
		                           "Id4 INTEGER NOT NULL," +
		                           "Id5 INTEGER NOT NULL," +
		                           "StatusID INTEGER NOT NULL," +
		                           "PRIMARY KEY(Id0,Id1,Id2,Id3,Id4,Id5)" +
		                           ");";
		const String TABLESTATUSNAME = "status";
		const String TABLESTATUS = "CREATE TABLE IF NOT EXISTS {0} (" +
		                           "Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT," +
		                           "Status INTEGER NOT NULL " +
		                           ");";
		public SqliteConnection Database;
		public Mutex DatabaseMutex;

		#endregion

		#region ECC Key

		public Byte[] EccPublicKey = {
			0x30, 0x6B,
			0x03, 0x02, 0x07, 0x00,
			0x02, 0x01, 0x30,
			// Curve X
			0x02, 0x30,
			0x23, 0xD8, 0x92, 0x7F, 0x07, 0x13, 0x94, 0x1E, 0xBD, 0x04, 0x43, 0xAE, 0x26, 0x5B, 0x9F, 0x5F,
			0x8A, 0xEF, 0x33, 0xC3, 0x75, 0xF3, 0x38, 0x32, 0x24, 0x64, 0xA6, 0xB7, 0xA8, 0x04, 0x8B, 0xE9,
			0x3F, 0x05, 0xD8, 0xA8, 0x76, 0xFB, 0x85, 0x83, 0x59, 0x0E, 0xEF, 0x5A, 0xB4, 0x6B, 0xAA, 0x43,
			// Cuve Y
			0x02, 0x30,
			0x54, 0xF6, 0xB7, 0x67, 0x03, 0xB6, 0x2B, 0xF6, 0x02, 0x08, 0xFA, 0x7A, 0xDE, 0xEA, 0x49, 0x77,
			0xDD, 0x5C, 0x26, 0x08, 0xF6, 0x70, 0xE7, 0x62, 0x92, 0xAA, 0xD3, 0xDA, 0x70, 0xB5, 0x50, 0xC3,
			0x6C, 0x42, 0x5D, 0x5E, 0x3B, 0xA7, 0x7E, 0x5A, 0xD4, 0xD9, 0x4A, 0xAB, 0x74, 0xB7, 0xF5, 0x9D
		};
		public Int32 EccPublicKeyCurveXOffset = 11;
		public Int32 EccPublicKeyCurveYOffset = 60;

		#endregion

		#region Block-based Cracking

		public Int32 BlockSize = 64;
		public BigInteger BlockMaximum;

		#endregion

		public void Run() {
			// Set up paths and create required folders.
			try { // Trycrash-Construct
				StorageKeyPath = String.Format("{0}\\Keys", StoragePath);
				StorageDatabasePath = String.Format("{0}\\Sqlite.db", StoragePath);

				Directory.CreateDirectory(StoragePath);
				Directory.CreateDirectory(StorageKeyPath);
				//Directory.CreateDirectory(StorageDatabasePath);
			} catch (Exception e) {
				Console.WriteLine(e);
				throw;
			}

			// Connect or create Sqlite database and setup tables, if they don't exist.
			try { // Trycrash-Construct
				Database = new SqliteConnection(new DbConnectionStringBuilder {
					{ "Uri", new Uri(@StorageDatabasePath).AbsoluteUri },
				}.ConnectionString);
				Database.Open();

				// Try create threads table.
				var createThreadsTableCmd = Database.CreateCommand();
				createThreadsTableCmd.CommandText = String.Format(TABLETHREADS, TABLETHREADSNAME);
				createThreadsTableCmd.ExecuteNonQuery();

				// Try create blocks table.
				var createBlocksTableCmd = Database.CreateCommand();
				createBlocksTableCmd.CommandText = String.Format(TABLEBLOCKS, TABLEBLOCKSNAME);
				createBlocksTableCmd.ExecuteNonQuery();

				// Try create stati table.
				var createStatiTableCmd = Database.CreateCommand();
				createStatiTableCmd.CommandText = String.Format(TABLESTATUS, TABLESTATUSNAME);
				createStatiTableCmd.ExecuteNonQuery();
			} catch (Exception e) {
				Console.WriteLine(e);
				throw;
			}

			DatabaseMutex = new Mutex();

			// Calculate Block limits.
			BlockMaximum = BigInteger.Divide(BigInteger.Pow(8, 48), BlockSize);

			// Create Threads.
			var crackerThreads = new CrackerThread[Environment.ProcessorCount];
			for (uint currentThreadId = 0; currentThreadId < Environment.ProcessorCount; currentThreadId++) {
				crackerThreads[currentThreadId] = new CrackerThread(this, currentThreadId);
				crackerThreads[currentThreadId].TryStart();
			}

			// Wait for user input to be 'stop'.
			String userCommand;
			while ((userCommand = Console.ReadLine()) != "stop") {
				Console.WriteLine("Unknown command: {0}", userCommand);
			}

			// Stop threads.
			for (uint proc = 0; proc < Environment.ProcessorCount; proc++) {
				crackerThreads[proc].TryStop();
			}

			Database.Close();
		}

		/// <summary>
		/// The entry point of the program, where the program control starts and ends.
		/// </summary>
		public static void Main() {
			ECCCracker myCracker = new ECCCracker();
			myCracker.Run();
		}

		class CrackerThread {
			const String THREADSELECT = "SELECT * FROM {0} WHERE Id0={1} AND Id1={2} AND Id2={3} AND Id3={4} AND Id4={5} AND Id5={6};";
			const String THREADINSERT = @"INSERT OR REPLACE INTO {0} (Id,Id0,Id1,Id2,Id3,Id4,Id5) VALUES ({1}, {2}, {3}, {4}, {5}, {6}, {7});";
			const String THREADDELETE = @"DELETE FROM {0} WHERE Id={1};";
			const String BLOCKSELECT = @"SELECT * FROM {0} WHERE Id0={1} AND Id1={2} AND Id2={3} AND Id3={4} AND Id4={5} AND Id5={6};";
			const String BLOCKINSERT = @"INSERT INTO {0} (Id0,Id1,Id2,Id3,Id4,Id5,StatusId) VALUES ({1}, {2}, {3}, {4}, {5}, {6}, {7});";
			const String STATUSSELECT = @"SELECT * FROM {0} WHERE Status={1};";
			const String STATUSINSERT = @"INSERT INTO {0} (Status) VALUES ({1});";
			ECCCracker parent = null;
			Random randomizer = null;
			Byte[] keyStore = null;
			UInt32 threadId = 0xFFFFFFFF;
			Thread thread = null;
			volatile bool doStop = false;

			public CrackerThread(ECCCracker parent, UInt32 threadId) {
				this.parent = parent;
				this.parent = parent;
				this.threadId = threadId;

				thread = new Thread(this.Callback);

				// Create useable key structure without keyscalar.
				keyStore = new byte[8 + 48 * 3];
				keyStore[0] = 0x45; // E
				keyStore[1] = 0x43; // C
				keyStore[2] = 0x4B; // K
				keyStore[3] = 0x34;
				keyStore[4] = 48; 
				Array.Copy(parent.EccPublicKey, parent.EccPublicKeyCurveXOffset, keyStore, 8, 48);
				Array.Copy(parent.EccPublicKey, parent.EccPublicKeyCurveYOffset, keyStore, 8 + 48, 48);
			}

			/// <summary>
			/// Tries to start.
			/// </summary>
			/// <returns><c>true</c>, if start was tried, <c>false</c> otherwise.</returns>
			public bool TryStart() {
				try {
					doStop = false;
					thread.Start();
					return true;
				} catch {
					return false;
				}
			}

			/// <summary>
			/// Tries to stop.
			/// </summary>
			/// <returns><c>true</c>, if stop was tried, <c>false</c> otherwise.</returns>
			public bool TryStop() {
				try {
					doStop = true;
					for (uint i = 0; i < 10; i++) {
						if (!thread.IsAlive)
							break;
						Thread.Sleep(100);
					}
					if (thread.IsAlive) {
						thread.Abort();
					}
					return true;
				} catch {
					return false;
				}
			}

			/// <summary>
			/// Callback for thread.
			/// </summary>
			/// <param name="stateInfo">State info.</param>
			private void Callback(Object stateInfo) {
				Thread.Sleep((int)((1000 / Environment.ProcessorCount) * threadId));
				Console.WriteLine("Thread {0}: Successfully started.", threadId);
				randomizer = new Random(Environment.TickCount);

				var blockStatus = new bool[64];
				while (!doStop) {
					BigInteger currentBlock = GetNextBlockId();
					var currentBlockByteArr = currentBlock.ToByteArray();
					Array.Resize(ref currentBlockByteArr, 48);

					var startingKeyId = BigInteger.Multiply(currentBlock, parent.BlockSize);
					for (int i = 0; i < parent.BlockSize; i++) {
						var currentKey = BigInteger.Add(startingKeyId, i);
						var currentKeyByteArr = currentKey.ToByteArray();
						Array.Resize(ref currentKeyByteArr, 48);

						try {
							// Add keyscalar to key and try to import it.
							Array.Copy(currentKeyByteArr, 0, keyStore, 8 + 48 + 48, 48);

							// Try and import the key.
							try {
								CngKey key = CngKey.Import(keyStore, CngKeyBlobFormat.EccPrivateBlob);

								try {
									File.WriteAllBytes(String.Format("{0}\\{1}-{2}.pkey",
									                                 parent.StorageKeyPath,
									                                 BitConverter.ToString(currentKeyByteArr, 0, 48).Replace(@"-", @""),
									                                 i),
									                   keyStore);
									blockStatus[i] = true;
									Console.WriteLine("Thread {0}: Success in block {1}.",
									                  threadId, BitConverter.ToString(currentBlockByteArr).Replace(@"-", @""));
								} catch (Exception e) {
									Console.WriteLine("Thread {0}: Failed to store key for block {1}.",
									                  threadId, BitConverter.ToString(currentBlockByteArr).Replace(@"-", @""));
									Console.WriteLine(e);
								}
							} catch {
								blockStatus[i] = false;
							}
						} catch (Exception e) {
							Console.WriteLine("Thread {0}: Critical error in block {1}.",
							                  threadId, BitConverter.ToString(currentBlockByteArr));
							Console.WriteLine(e);
							doStop = true;
						}
					}

					if (!doStop) {
						SetBlockState(currentBlockByteArr, blockStatus);
					}

					// Sleep to make system responsive.
					Thread.Sleep(1);
				}

				if (doStop)
					Console.WriteLine("Thread {0}: Successfully stopped.", threadId);
			}

			/// <summary>
			/// Gets the next block identifier.
			/// </summary>
			/// <returns>The next block identifier.</returns>
			BigInteger GetNextBlockId() {
				BigInteger newBlockId = -1;
				Byte[] newBlockData = new Byte[48 + 1];

				parent.DatabaseMutex.WaitOne();
				bool isValid0 = false, isValid1 = false;
				while ((isValid0 == false || isValid1 == false) && BigInteger.Compare(newBlockId, parent.BlockMaximum) <= 0) {
					isValid0 = isValid1 = false;

					// Generate random number.
					randomizer.NextBytes(newBlockData);
					newBlockData[47] = (byte)(newBlockData[47] & 0x03); // Using 6 bits less than maximum.
					newBlockData[48] = 0x00;
					newBlockId = new BigInteger(newBlockData);

					// Check if the block id is already being used.
					try { //Trycrash-Construct
						var checkThreadUsageCmd = new SqliteCommand(String.Format(@THREADSELECT,
						                                                          @ECCCracker.TABLETHREADSNAME,
						                                                          BitConverter.ToUInt64(newBlockData, 0),
						                                                          BitConverter.ToUInt64(newBlockData, 8),
						                                                          BitConverter.ToUInt64(newBlockData, 16),
						                                                          BitConverter.ToUInt64(newBlockData, 24),
						                                                          BitConverter.ToUInt64(newBlockData, 32),
						                                                          BitConverter.ToUInt64(newBlockData, 40)), parent.Database);
						var checkThreadUsageReader = checkThreadUsageCmd.ExecuteReader();
						if (checkThreadUsageReader.HasRows) {// If there are rows containing this item, continue with generating the next number
							checkThreadUsageReader.Close();
							continue;
						}
						checkThreadUsageReader.Close();
						isValid0 = true;
					} catch (Exception e) {
						Console.WriteLine("Thread {0}: Encountered Exception while trying to get next block Id:", threadId);
						Console.WriteLine(e);
						Console.ReadKey();
					}

					// Check if the block id has already been used.
					try {
						var checkBlockDoneCmd = new SqliteCommand(String.Format(@BLOCKSELECT,
						                                                        @ECCCracker.TABLEBLOCKSNAME,
						                                                        BitConverter.ToUInt64(newBlockData, 0),
						                                                        BitConverter.ToUInt64(newBlockData, 8),
						                                                        BitConverter.ToUInt64(newBlockData, 16),
						                                                        BitConverter.ToUInt64(newBlockData, 24),
						                                                        BitConverter.ToUInt64(newBlockData, 32),
						                                                        BitConverter.ToUInt64(newBlockData, 40)), parent.Database);
						var checkThreadUsageReader = checkBlockDoneCmd.ExecuteReader();
						if (checkThreadUsageReader.HasRows) {// If there are rows containing this item, continue with generating the next number
							checkThreadUsageReader.Close();
							continue;
						}
						checkThreadUsageReader.Close();
						isValid1 = true;
					} catch (Exception e) {
						Console.WriteLine("Thread {0}: Encountered Exception while trying to get next block Id:", threadId);
						Console.WriteLine(e);
						Console.ReadKey();
					}
				}

				// Now set the block id as being used.
				try {
					var setBlockUsedCmd = new SqliteCommand(String.Format(@THREADINSERT,
					                                                      @ECCCracker.TABLETHREADSNAME,
					                                                      threadId,
					                                                      BitConverter.ToUInt64(newBlockData, 0),
					                                                      BitConverter.ToUInt64(newBlockData, 8),
					                                                      BitConverter.ToUInt64(newBlockData, 16),
					                                                      BitConverter.ToUInt64(newBlockData, 24),
					                                                      BitConverter.ToUInt64(newBlockData, 32),
					                                                      BitConverter.ToUInt64(newBlockData, 40)), parent.Database);
					setBlockUsedCmd.ExecuteNonQuery();
				} catch (Exception e) {
					Console.WriteLine("Thread {0}: Encountered Exception while trying to get next block Id:", threadId);
					Console.WriteLine(e);
					Console.ReadKey();
				}
				parent.DatabaseMutex.ReleaseMutex();

				return newBlockId;
			}

			void SetBlockState(byte[] blockId, bool[] status) {
				UInt64 statusValue = 0;
				UInt64 statusId = 0;

				// Build 64bit value.
				for (byte valuePos = 0; valuePos < 64; valuePos++) {
					statusValue += (status[valuePos] ? 1ul : 0ul) << valuePos;
				}

				// Try and get a valid status id.
				try {
					parent.DatabaseMutex.WaitOne();
					var selectStatusCmd = new SqliteCommand(String.Format(@STATUSSELECT,
					                                                      ECCCracker.TABLESTATUSNAME,
					                                                      statusValue), parent.Database);
					var selectStatusReader = selectStatusCmd.ExecuteReader();
					if (selectStatusReader.HasRows) {
						selectStatusReader.NextResult();
						statusId = (UInt64)selectStatusReader.GetInt64(0);
					} else {
						var insertStatusCmd = new SqliteCommand(String.Format(@STATUSINSERT,
						                                                      ECCCracker.TABLESTATUSNAME,
						                                                      statusValue), parent.Database);
						insertStatusCmd.ExecuteNonQuery();
						var lastInsertIdCmd = new SqliteCommand("SELECT last_insert_rowid();", parent.Database);
						var lastInsertIdReader = lastInsertIdCmd.ExecuteReader();
						lastInsertIdReader.NextResult();
						statusId = (UInt64)lastInsertIdReader.GetInt64(0);
						lastInsertIdReader.Close();
					}
					selectStatusReader.Close();
				} catch (Exception e) {
					Console.WriteLine("Thread {0}: Encountered Exception while marking block as complete:", threadId);
					Console.WriteLine(e);
					Console.ReadKey();
				} finally {
					parent.DatabaseMutex.ReleaseMutex();
				}

				// Try and mark block as complete.
				try {
					parent.DatabaseMutex.WaitOne();
					var insertBlockCmd = new SqliteCommand(String.Format(@BLOCKINSERT,
					                                                     ECCCracker.TABLEBLOCKSNAME,
					                                                     BitConverter.ToUInt64(blockId, 0),
					                                                     BitConverter.ToUInt64(blockId, 8),
					                                                     BitConverter.ToUInt64(blockId, 16),
					                                                     BitConverter.ToUInt64(blockId, 24),
					                                                     BitConverter.ToUInt64(blockId, 32),
					                                                     BitConverter.ToUInt64(blockId, 40),
					                                                     statusId), parent.Database);
					insertBlockCmd.ExecuteNonQuery();
					var lastInsertIdCmd = new SqliteCommand("SELECT last_insert_rowid();", parent.Database);
					var lastInsertIdReader = lastInsertIdCmd.ExecuteReader();
					lastInsertIdReader.NextResult();
					UInt64 blockRowId = (UInt64)lastInsertIdReader.GetInt64(0);
					lastInsertIdReader.Close();
					if (blockRowId == 0)
						Console.WriteLine("Thread {0}: Failed to mark block as complete.", threadId);
				} catch (Exception e) {
					Console.WriteLine("Thread {0}: Encountered Exception while marking block as complete:", threadId);
					Console.WriteLine(e);
					Console.ReadKey();
				} finally {
					parent.DatabaseMutex.ReleaseMutex();
				}
			}
		}
	}
}