namespace sl.crypto.elgamal.keys
{
	using sl.crypto.elgamal.parameter;
	using sl.crypto.util;
	/**
	 * <summary>
 	 * Autor: Matthias Koch
 	 * Version: 0.5
 	 * 
 	 * Klasse welche ein konkretes Objekt für die Darstellung des öffentlichen Schlüssels
 	 * darstellt.
 	 * </summary>  
 	 */
	public class PublicKey : Key
	{
		private BigInteger y;
		//erlaube lesenden Zugriff
		public BigInteger Y
		{
			get{return y;} 
		}
		/**
		 * 
		 * <param name="y"/>
		 * <param name="params"/>
		 */
		public PublicKey(BigInteger y, Parameter parameter):base(false, parameter)
		{			
			this.y = y;
		}
		/**
		 * 
		 */
		public bool equals(object obj)
		{
			if (!(obj is PublicKey))
			{
				return false;
			}
			PublicKey pKey = (PublicKey) obj;
			if (!pKey.Y.Equals(y))
			{
				return false;
			}
			return Equals(obj);
		}
	}
}
