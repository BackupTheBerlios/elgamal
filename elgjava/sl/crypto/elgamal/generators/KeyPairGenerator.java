package sl.crypto.elgamal.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import sl.crypto.elgamal.keys.PrivateKey;
import sl.crypto.elgamal.keys.PublicKey;
import sl.crypto.elgamal.parameter.Parameter;
/**
 * Klasse welche ein Objekt zur erzeugung eines Schlüsselpaares repräsentiert.
 * 
 * @author Matthias Koch
 * @version 0.5   
 */
public class KeyPairGenerator
{
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	private Parameter params;
	private SecureRandom random;
	private int strength;
	/**
	 * 
	 * @param random
	 * @param params
	 */	
	public KeyPairGenerator(SecureRandom random, Parameter params)
	{
		this.params = params;
		this.random = random;
		this.strength = params.getP().bitLength() - 1;
		this.generateKeyPair();
	}
	/**
	 * gibt den öffentlichen Schlüssel zurück
	 *
	 * @return the public key parameters.
	 */
	public PublicKey getPublic()
	{
		return publicKey;
	}
	/**
	 * gibt den privaten Schlüssel zurück
	 *
	 * @return the private key parameters.
	 */
	public PrivateKey getPrivate()
	{
		return privateKey;
	}

	/**
	 * 
	 */
	private void generateKeyPair()
	{
		BigInteger p, g, x, y;
		int qLength = this.strength - 1;
		p = params.getP();
		g = params.getG();
		//
		// berechne den private key
		//		
		x = new BigInteger(qLength, this.random);
		//
		// berechnde den public key.
		//
		y = g.modPow(x, p);
		this.publicKey = new PublicKey(y, params);
		this.privateKey = new PrivateKey(x, params);		
	}
}
