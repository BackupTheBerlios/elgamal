package sl.crypto.elgamal.keys;

import java.math.BigInteger;

import sl.crypto.elgamal.parameter.Parameter;

/**
 * Klasse welche ein konkretes Objekt für die Darstellung des privaten Schlüssels
 * darstellt.
 * 
 * @author Matthias Koch
 * @version 0.5 
 */
public class PrivateKey extends Key
{
	private BigInteger x;
	/**
	 * 
	 * @param x
	 * @param params
	 */
	public PrivateKey(BigInteger x, Parameter params)
	{
		super(true, params);
		this.x = x;
	}
	/**
	 * 
	 * @return BigInteger x
	 */
	public BigInteger getX()
	{
		return x;
	}
	/**
	 * 
	 */
	public boolean equals(Object obj)
	{
		if (!(obj instanceof PrivateKey))
		{
			return false;
		}
		PrivateKey pKey = (PrivateKey) obj;
		if (!pKey.getX().equals(x))
		{
			return false;
		}
		return super.equals(obj);
	}
}