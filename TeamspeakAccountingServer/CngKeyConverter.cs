using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Bcpg;
using System.Diagnostics;
using System.IO;
using Org.BouncyCastle.Asn1.Utilities;

namespace TeamspeakAccountingServer {
	public class CngKeyConverter {
		public CngKeyConverter() {
		}

		public static CngKey Import(Byte[] blob,
		                            Int32 offset = 0) {
			Boolean isPrivateKey = false;
			Byte keyLength = 0;
			Byte[] keyCurveX = null, keyCurveY = null, keyScalar = null;
			Byte[] inBlob = blob;

			// Apply offset to incoming data.
			if (offset > 0) {
				var blobLength = blob.Length - (offset);
				inBlob = new Byte[blobLength];
				Array.Copy(blob, offset, inBlob, 0, blobLength);
			}
			System.IO.File.WriteAllBytes("Key.key", inBlob);

			DerSequence der = (DerSequence)DerSequence.FromByteArray(inBlob);
			try { /*to read directly*/
				isPrivateKey = ((DerBitString)der[0]).IntValue != 0;
			} catch {
				der = (DerSequence)DerSequence.FromByteArray(((DerOctetString)der[1]).GetOctets());
				System.IO.File.WriteAllBytes("KeyDer.key", der.GetEncoded());
			}

			// Read Data from Key.
			isPrivateKey = ((DerBitString)der[0]).IntValue != 0;
			keyLength = (Byte)((DerInteger)der[1]).PositiveValue.IntValue;
			keyCurveX = ((DerInteger)der[2]).PositiveValue.ToByteArrayUnsigned();
			keyCurveY = ((DerInteger)der[3]).PositiveValue.ToByteArrayUnsigned();
			if (isPrivateKey)
				keyScalar = ((DerInteger)der[4]).PositiveValue.ToByteArrayUnsigned();

			// Validate data.
			if (keyLength == 0)
				throw new IndexOutOfRangeException("Length of key is 0.");
			if (keyCurveX == null || keyCurveY == null)
				throw new IndexOutOfRangeException("Key Curve is not set.");

			// Construct a readable key out of this data.
			Byte[] newBlob = new Byte[8 + (keyLength * (2 + (isPrivateKey ? 1 : 0)))];

			// Write Key Header for ECCPrivateBlob or ECCPublicBlob.
			newBlob[0] = (Byte)0x45; // E
			newBlob[1] = (Byte)0x43; // C
			newBlob[2] = (Byte)0x4B; // K
			newBlob[3] = (Byte)(keyLength == 32 ? 0x31 : (keyLength == 48 ? 0x33 : (keyLength == 64 ? 0x35 : 0x00)));
			newBlob[3] += (Byte)(isPrivateKey ? 0x01 : 0x00);
			newBlob[4] = (Byte)keyLength;

			Array.Copy(keyCurveX, 0, newBlob, 8, keyCurveX.Length);
			Array.Copy(keyCurveY, 0, newBlob, 8 + keyLength, keyCurveY.Length);
			if (isPrivateKey)
				Array.Copy(keyScalar, 0, newBlob, 8 + keyLength * 2, keyScalar.Length);

			// Now return a valid Key.
			if (isPrivateKey)
				return CngKey.Import(newBlob, CngKeyBlobFormat.EccPrivateBlob);
			else
				return CngKey.Import(newBlob, CngKeyBlobFormat.EccPublicBlob);
		}
	}
}

