namespace sl.crypto.elgamal
{
	using sl.crypto.elgamal.exceptions;
	using sl.crypto.elgamal.keys;
	using sl.crypto.util;
	using System;
	
	/**
	 * <summary>
 	 * Autor: Matthias Koch
 	 * Version: 0.5
 	 * 
 	 * Klasse welche welche ein Objekt repräsentiert mit welcher ein Text nach ElGamal 
 	 * ver und entschlüsselt werden kann.
 	 * </summary>
 	 */
	public class ElGamal
	{
		private Key key;
		private Random random;
		private bool encrypt;
		private static BigInteger ZERO = new BigInteger(0);
		private static BigInteger ONE = new BigInteger(1);
		private static BigInteger TWO = new BigInteger(2);
		/**
		 * <summary>
	 	 * initialisierung der ElGamal Engine
	 	 * </summary>
	 	 * <param name="encrypt"> true wenn die Nachricht verschlüsselt werden soll</param>
	  	 * <param name="key"> der für die jeweilige Operation benötige öffentliche bzw. private Schlüssel</param>
	 	 */
		public void init(bool encrypt, Key key)
		{
			this.key = key;
			this.random = new Random();
			this.encrypt = encrypt;		
		}
		/**
		 * <returns> int - maximale größe der Nachricht</returns> 
		 */
		public int getInputBlockSize()
		{
			int bitSize = key.Parameter.P.bitCount();
			if (encrypt)
			{
				if ((bitSize % 8) == 0)
				{
					return bitSize / 8 - 1;
				}
				return bitSize / 8;
			}
			else
			{
				return 2 * (((bitSize - 1) + 7) / 8);
			}
		}
		/**
		 * <returns> int - maximale größe des Chippertextes</returns>
		 */
		public int getOutputBlockSize()
		{
			int bitSize = key.Parameter.P.bitCount();
			if (encrypt)
			{
				return 2 * (((bitSize - 1) + 7) / 8);
			}
			else
			{
				return (bitSize - 7) / 8;
			}
		}
		/**
		 * <summary>
		 * verarbeite die eingehende Nachricht
		 * </summary>
		 * <param name="in"> eingehende Nachricht als array.</param>
		 * <param name="inOff"> der Zeiger auf das erste Inhaltsemelent.</param>
		 * <param name="inLen> die Anzahl der Zeichen welche verarbeitet werden sollen.</param>
		 * <returns> gibt die ver- bzw. entschlüsselte Nachricht zurück.</returns>
		 * <exception cref="sl.crypto.elgamal.exceptions.DataLengthException"> die eingehende Nachricht ist zu lang.</exception>
		 */
		public byte[] processBlock(byte[] input, int inOff, int inLen)
		{
			if (inLen > (getInputBlockSize() + 1))
			{		
				throw new DataLengthException("Nachricht zu groß für diesen ElGamal Schlüssel.\n");
			}
			else if (inLen == (getInputBlockSize() + 1) && (input[inOff] & 0x80) != 0)
			{			
				throw new DataLengthException("Nachricht zu groß für diesen ElGamal Schlüssel.\n");
			}		
			byte[] block;
			if (inOff != 0 || inLen != input.Length)
			{
				block = new byte[inLen];
				Array.Copy(input, inOff, block, 0, inLen);
			}
			else
			{
				block = input;
			}
			BigInteger g = key.Parameter.G;
			BigInteger p = key.Parameter.P;
			if (key is PrivateKey)
			{
				byte[] in1 = new byte[block.Length / 2];
				byte[] in2 = new byte[block.Length / 2];
				System.Array.Copy(block, 0, in1, 0, in1.Length);
				System.Array.Copy(block, in1.Length, in2, 0, in2.Length);
				BigInteger a = new BigInteger(in1);
				BigInteger b = new BigInteger(in2);
				PrivateKey priv = (PrivateKey) key;
				BigInteger m = a.modPow(p - ONE - priv.X,p) * b % p;
				byte[] output = m.getBytes();
				if (output[0] != 0)
				{
					return output;
				}
				else
				{
					byte[] newoutput = new byte[output.Length - 1];
					Array.Copy(output, 1, newoutput, 0, newoutput.Length);
					return newoutput;
				}
			}
			else
			{
				PublicKey pub = (PublicKey) key;
				BigInteger newinput = new BigInteger(block);
				int pBitLength = p.bitCount();
				BigInteger k = new BigInteger();
				k.genRandomBits(pBitLength, random);
				while (k.Equals(ZERO) || (k > (p - TWO)))
				{
					k = new BigInteger();
					k.genRandomBits(pBitLength, random);
				}
				BigInteger a = g.modPow(k, p);
				BigInteger b = newinput * (pub.Y.modPow(k, p)) % (p);
				byte[] out1 = a.getBytes();
				byte[] out2 = b.getBytes();
				byte[] output = new byte[this.getOutputBlockSize()];
				if (out1.Length > output.Length / 2)
				{
					Array.Copy(out1, 1, output, output.Length / 2 - (out1.Length - 1), out1.Length - 1);
				}
				else
				{
					Array.Copy(out1, 0, output, output.Length / 2 - out1.Length, out1.Length);
				}
				if (out2.Length > output.Length / 2)
				{
					Array.Copy(out2, 1, output, output.Length - (out2.Length - 1), out2.Length - 1);
				}
				else
				{
					Array.Copy(out2, 0, output, output.Length - out2.Length, out2.Length);
				}
				return output;
			}
		}
	}
}
