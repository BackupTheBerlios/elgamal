package sl.crypto.elgamal.parameter;
import java.math.BigInteger;
import java.security.SecureRandom;
/**
 * Parameter Klasse welche ein Objekt repräsentiert mit welchem die für den ElGamal
 * Algorithmus benötigen Parameter: p Primzahl und g primitive Wurzel gefunden werden
 * 
 * @author Matthias Koch
 * @version 0.5
 */
public class Parameter
{
	private BigInteger g;
	private BigInteger p;
	//
	private int size;
	private int certainty;
	private SecureRandom random;
	//
	private static final BigInteger ONE = BigInteger.valueOf(1);
	private static final BigInteger TWO = BigInteger.valueOf(2);
	/**
	 * 
	 * @param size
	 * @param certainty
	 * @param random
	 */
	public Parameter(int size, int certainty, SecureRandom random)
	{
		this.size = size;
		this.certainty = certainty;
		this.random = random;
		this.generateParameters();
	}
	/**
	 * finde eine sichere große Primzahl p und eine primitive Wurzel g mit den 
	 * angegebenen Parametern 
	 */
	private void generateParameters()
	{
		BigInteger g, p, q;
		int qLength = size - 1;
		// finde eine sichere große Primzahl p durch 2*q + 1, q ist ebenfalls eine Primzahl
		while(true)
		{
			q = new BigInteger(qLength, 1, random);			
			if (q.bitLength() != qLength)
			{
				continue;
			}
			if (!q.isProbablePrime(certainty))
			{
				continue;
			}
			p = q.multiply(TWO).add(ONE);
			if (p.isProbablePrime(certainty))
			{
				break;
			}
		}
		this.p = p;
		// berechne g durch 2q+1
		while (true)
		{
			g = new BigInteger(qLength, random);
			if (g.modPow(TWO, p).equals(ONE))
			{
				continue;
			}
			if (g.modPow(q, p).equals(ONE))
			{
				continue;
			}
			break;
		}
		this.g = g;
	}
	/**
	 * @param p
	 * @param g
	 */
	public Parameter(BigInteger p, BigInteger g)
	{
		this.g = g;
		this.p = p;
	}
	/**
	 * 
	 * @return BigInteger p
	 */
	public BigInteger getP()
	{
		return p;
	}
	/**
	 * @return BigInteger g
	 */
	public BigInteger getG()
	{
		return g;
	}
	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(Object objekt)
	{
		if (!(objekt instanceof Parameter))
		{
			return false;
		}
		Parameter pm = (Parameter) objekt;
		return pm.getP().equals(p) && pm.getG().equals(g);
	}
}
