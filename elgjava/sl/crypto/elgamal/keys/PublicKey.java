package sl.crypto.elgamal.keys;

import java.math.BigInteger;

import sl.crypto.elgamal.parameter.Parameter;
/**
 *  Klasse welche ein konkretes Objekt für die Darstellung des öffentlichen Schlüssels
 * darstellt.
 * 
 * @author Matthias Koch
 * @version 0.5 
 */
public class PublicKey extends Key
{
	private BigInteger y;
	/**
	 * 
	 * @param y
	 * @param params
	 */
	public PublicKey(BigInteger y, Parameter params)
	{
		super(false, params);
		this.y = y;
	}
	/**
	 * 
	 * @return Biginteger y
	 */
	public BigInteger getY()
	{		
		return y;
	}
	/**
	 * 
	 */
	public boolean equals(Object obj)
	{
		if (!(obj instanceof PublicKey))
		{
			return false;
		}
		PublicKey pKey = (PublicKey) obj;
		if (!pKey.getY().equals(y))
		{
			return false;
		}
		return super.equals(obj);
	}
}
