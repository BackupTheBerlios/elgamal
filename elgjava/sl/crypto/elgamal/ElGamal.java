package sl.crypto.elgamal;

import java.math.BigInteger;
import java.security.SecureRandom;

import sl.crypto.elgamal.exceptions.DataLengthException;
import sl.crypto.elgamal.keys.Key;
import sl.crypto.elgamal.keys.PrivateKey;
import sl.crypto.elgamal.keys.PublicKey;
/**
 * Klasse welche welche ein Objekt repräsentiert mit welcher ein Text nach ElGamal 
 * ver und entschlüsselt werden kann.
 * 
 * @author Matthias Koch
 * @version 0.5 
 */
public class ElGamal
{
	private Key key;
	private SecureRandom random;
	private boolean encrypt;
	private static final BigInteger ZERO = BigInteger.valueOf(0);
	private static final BigInteger ONE = BigInteger.valueOf(1);
	private static final BigInteger TWO = BigInteger.valueOf(2);
	/**
	 * initialisierung der ElGamal Engine
	 *
	 * @param encrypt true wenn die Nachricht verschlüsselt werden soll
	 * @param key der für die jeweilige Operation benötige öffentliche bzw. 
	 * private Schlüssel
	 */
	public void init(boolean encrypt, Key key)
	{
		this.key = key;
		this.random = new SecureRandom();
		this.encrypt = encrypt;
	}
	/**
	 * @return int - maximale größe der Nachricht 
	 */
	private int getInputBlockSize()
	{
		int bitSize = key.getParameters().getP().bitLength();
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
	 * @return int - maximale größe des Chippertextes
	 */
	private int getOutputBlockSize()
	{
		int bitSize = key.getParameters().getP().bitLength();
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
	 * verarbeite die eingehende Nachricht
	 *
	 * @param in the input array.
	 * @param inOff the offset into the input buffer where the data starts.
	 * @param inLen the length of the data to be processed.
	 * @return the result of the ElGamal process.
	 * @exception DataLengthException the input block is too large.
	 */
	public byte[] processBlock(byte[] in, int inOff, int inLen)
	{		
		if (inLen > (getInputBlockSize() + 1))
		{		
			throw new DataLengthException("Nachricht zu groß für diesen ElGamal Schlüssel.\n");
		}
		else if (inLen == (getInputBlockSize() + 1) && (in[inOff] & 0x80) != 0)
		{			
			throw new DataLengthException("Nachricht zu groß für diesen ElGamal Schlüssel.\n");
		}		
		byte[] block;
		if (inOff != 0 || inLen != in.length)
		{
			block = new byte[inLen];
			System.arraycopy(in, inOff, block, 0, inLen);
		}
		else
		{
			block = in;
		}
		BigInteger g = key.getParameters().getG();
		BigInteger p = key.getParameters().getP();
		if (key instanceof PrivateKey)
		{
			byte[] in1 = new byte[block.length / 2];
			byte[] in2 = new byte[block.length / 2];
			System.arraycopy(block, 0, in1, 0, in1.length);
			System.arraycopy(block, in1.length, in2, 0, in2.length);
			BigInteger a = new BigInteger(1, in1);
			BigInteger b = new BigInteger(1, in2);
			PrivateKey priv = (PrivateKey) key;
			BigInteger m = a.modPow(p.subtract(ONE).subtract(priv.getX()), p).multiply(b).mod(p);
			byte[] out = m.toByteArray();
			if (out[0] != 0)
			{
				return out;
			}
			else
			{
				byte[] output = new byte[out.length - 1];
				System.arraycopy(out, 1, output, 0, output.length);
				return output;
			}
		}
		else
		{
			PublicKey pub = (PublicKey) key;
			BigInteger input = new BigInteger(1, block);
			int pBitLength = p.bitLength();
			BigInteger k = new BigInteger(pBitLength, random);
			while (k.equals(ZERO) || (k.compareTo(p.subtract(TWO)) > 0))
			{
				k = new BigInteger(pBitLength, random);
			}
			BigInteger a = g.modPow(k, p);
			BigInteger b = input.multiply(pub.getY().modPow(k, p)).mod(p);
			byte[] out1 = a.toByteArray();
			byte[] out2 = b.toByteArray();
			byte[] output = new byte[this.getOutputBlockSize()];
			if (out1.length > output.length / 2)
			{
				System.arraycopy(out1, 1, output, output.length / 2 - (out1.length - 1), out1.length - 1);
			}
			else
			{
				System.arraycopy(out1, 0, output, output.length / 2 - out1.length, out1.length);
			}
			if (out2.length > output.length / 2)
			{
				System.arraycopy(out2, 1, output, output.length - (out2.length - 1), out2.length - 1);
			}
			else
			{
				System.arraycopy(out2, 0, output, output.length - out2.length, out2.length);
			}
			return output;
		}
	}
}
