package sl.crypto.elgamal.keys;

import sl.crypto.elgamal.parameter.Parameter;

/**
 * Apstrakte Klasse welche ein Key Objekt beschreibt
 * 
 * @author Matthias Koch
 * @version 0.5  
 */
public abstract class Key
{
	private Parameter params;
	boolean privateKey;
	/**
	 * 
	 * @return boolean - gibt an ob es sich um einen privaten Schlüssel handelt
	 */
	public boolean isPrivate()
	{
		return privateKey;
	}
	/**
	 * 
	 * @param isPrivate
	 * @param params
	 */
	protected Key(boolean isPrivate, Parameter params)
	{
		this.privateKey = isPrivate;
		this.params = params;
	}
	/**
	 * 
	 * @return Parameter gibt die Paramter des Schlüssels zurück 
	 */
	public Parameter getParameters()
	{
		return params;
	}
	/**
	 * 
	 */
	public boolean equals(Object obj)
	{
		if (!(obj instanceof Key))
		{
			return false;
		}
		Key dhKey = (Key) obj;
		return (params != null && !params.equals(dhKey.getParameters()));
	}
}
