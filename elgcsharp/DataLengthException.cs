namespace sl.crypto.elgamal.exceptions
{
	/**
	 *
	 * Ausnahme wenn der die eingehende/ausgehende Nachricht zu groß ist.
	 *
	 */
	public class DataLengthException : System.Exception
	{
		/**
		 * 
		 */
		public DataLengthException()
		{
		}
		/**		 
		 *
		 * @param message die Mitteilung welche die Ausnahme ausgeben kann.
		 */
		public DataLengthException(string message):base(message)
		{
		}
	}
}