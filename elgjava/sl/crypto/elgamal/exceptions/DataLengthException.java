package sl.crypto.elgamal.exceptions;
/**
 * Ausnahme wenn der die eingehende/ausgehende Nachricht zu groﬂ ist.
 */
public class DataLengthException extends RuntimeException
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
	public DataLengthException(String message)
	{
		super(message);
	}
}
