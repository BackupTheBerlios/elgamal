namespace sl.crypto.elgamal.parameter
{	
	using sl.crypto.util;
	
	using System;
	
	/**
	 * <summary>
 	 * Autor: Matthias Koch
  	 * Version: 0.5
 	 * 
 	 * Parameter Klasse welche ein Objekt repräsentiert mit welchem die für den ElGamal
 	 * Algorithmus benötigen Parameter: p Primzahl und g primitive Wurzel gefunden werden
 	 * </summary> 
 	 */
	public class Parameter
	{
		private BigInteger g;
		//lesender Zugriff auf g
		public BigInteger G
		{
			get{return g;}
		}
		private BigInteger p;
		//lesender Zugriff auf p
		public BigInteger P
		{
			get{return p;}
		}
		//
		private int size;
		private int certainty;
		private Random random;
		//
		private readonly BigInteger ONE = new BigInteger(1);
		private readonly BigInteger TWO = new BigInteger(2);	
		/**
		 * 
		 * <param name="size"/>
		 * <param name="certainty"/>
		 * <param name="random"/>
		 */
		public Parameter(int size, int certainty, Random random)
		{
			this.size = size;
			this.certainty = certainty;
			this.random = random;
			this.generateParameters();
		}
		/**
		 * <summary>
		 * finde eine sichere große Primzahl p und eine primitive Wurzel g mit den 
	  	 * angegebenen Parametern
	  	 * </summary> 
	 	 */
		private void generateParameters()
		{
			BigInteger g, p, q;
			int qLength = size - 1;
			// finde eine sichere große Primzahl p durch 2*q + 1, q ist ebenfalls eine Primzahl
			while(true)
			{
				q = new BigInteger();
				q.genRandomBits(qLength,random);
				if (q.bitCount() != qLength)
				{
					continue;
				}
				if (!q.isProbablePrime(certainty))
				{
					continue;
				}
				p = q*(TWO)+(ONE);
				if (p.isProbablePrime(certainty))
				{
					break;
				}
			}
			this.p=p;
			// berechne g durch 2q+1while(true)
			while(true)
			{
				g = new BigInteger();
				g.genRandomBits(qLength, random);
				if (g.modPow(TWO, p).Equals(ONE))
				{
					continue;
				}
				if (g.modPow(q, p).Equals(ONE))
				{
					continue;
				}
				break;
			}
			this.g=g;
		}	
		/**
		 * 
		 * <param name="p"/>
		 * <param name="g"/>
		 */
		public Parameter(BigInteger p, BigInteger g)
		{
			this.g = g;
			this.p = p;
		}		
		public bool equals(object objekt)
		{
			if (!(objekt is Parameter))
			{
				return false;
			}
			Parameter pm = (Parameter) objekt;
			return pm.P.Equals(p) && pm.G.Equals(g);
		}
	}
}