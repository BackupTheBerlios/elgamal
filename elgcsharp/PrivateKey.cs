namespace sl.crypto.elgamal.keys
{
	using sl.crypto.elgamal.parameter;
	using sl.crypto.util;
	/**
	 * <summary>
 	 * Autor: Matthias Koch
 	 * Version: 0.5
 	 * 
 	 * Klasse welches ein konkretes Objekt für die Darstellung des privaten Schlüssels
 	 * darstellt.
 	 * </summary> 
 	 */
	public class PrivateKey : Key
	{
		private BigInteger x;
		//erlaube lesenden Zugriff
		public BigInteger X
		{
			get{return x;}
		}
		/**
		 * 
		 * <param name="x"/>
		 * <param name="params"/>
		 */
		public PrivateKey(BigInteger x, Parameter parameter):base(true, parameter)
		{			
			this.x = x;
		}
		/**
		 * 
		 */
		public bool equals(object obj)
		{
			if (!(obj is PrivateKey))
			{
				return false;
			}			
			PrivateKey pKey = (PrivateKey) obj;
			if (!pKey.X.Equals(x))
			{
				return false;
			}
			return Equals(obj);
		}
	}
}