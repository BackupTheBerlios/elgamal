namespace sl.crypto.elgamal.keys
{
	using sl.crypto.elgamal.parameter;
	/**
	 * <summary>
 	 * Autor: Matthias Koch
 	 * Version: 0.5
 	 * 
 	 * Apstrakte Klasse welche ein Key Objekt beschreibt
 	 * </summary> 
 	 */
	public abstract class Key
	{
		private Parameter parameter;
		//erlaube lesenden Zugriff
		public Parameter Parameter
		{
			get{return parameter;}
		}
		private bool privateKey;
		//erlaube lesenden Zugriff
		public bool isPrivateKey
		{
			get{return privateKey;}
		}
		/**
		 * 
		 * <param name="isPrivate"/>
		 * <param name="params"/>
		 */
		protected Key(bool isPrivate, Parameter parameter)
		{
			this.privateKey = isPrivate;
			this.parameter = parameter;
		}
		/**
		 * 
		 */
		public new bool Equals(object obj)
		{
			if (!(obj is Key))
			{
				return false;
			}
			Key dhKey = (Key) obj;
			return (parameter != null && !parameter.Equals(dhKey.Parameter));
		}
	}
}