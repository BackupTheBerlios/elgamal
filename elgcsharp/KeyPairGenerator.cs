namespace sl.crypto.elgamal.generators
{	
	using sl.crypto.elgamal.keys;	
	using sl.crypto.elgamal.parameter;
	using sl.crypto.util;	
	
	using System;

	/**
	 * <summary>
 	 * Autor: Matthias Koch
 	 * Version: 0.5
 	 * 
 	 * Klasse welche ein Objekt zur erzeugung eines Schlüsselpaares repräsentiert.
 	 * </summary> 
	 */
	public class KeyPairGenerator
	{
		private PublicKey publicKey;
		// erlaube lesenden Zugriff
		public PublicKey PublicKey
		{
			get{return publicKey;}
		}
		private PrivateKey privateKey;
		//erlaube lesenden Zugrriff
		public PrivateKey PrivateKey
		{
			get{return privateKey;}
		}
	
		private Parameter parameter;
		private Random random;
		private int strength;
	
		/**
		 * 
		 * <param name="random"/>
		 * <param name="params"/>
		 */	
		public KeyPairGenerator(Random random, Parameter parameter)
		{
			this.parameter = parameter;
			this.random = random;
			this.strength = parameter.P.bitCount() - 1;			
			this.generateKeyPair();
		}
		/**
		 *
		 */
		private void generateKeyPair()
		{
			BigInteger p, g, x, y;			
			int qLength = strength - 1;
			p = parameter.P;			
			g = parameter.G;
			//
			// berechne den private key
			//
			x = new BigInteger();
			x.genRandomBits(qLength, random);
			//
			// berechne den public key.
			//
			y = g.modPow(x, p);
			this.publicKey = new PublicKey(y, parameter);
			this.privateKey = new PrivateKey(x, parameter);			
		}
	}
}