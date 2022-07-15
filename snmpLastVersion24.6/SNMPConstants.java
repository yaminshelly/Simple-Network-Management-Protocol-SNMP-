package source.com.snmp;

public class SNMPConstants
{
	public static byte SNMP_VERSION = 0x02;
	public static String COMMUNITY_STRING = "PRIVATE";

	//ASN1 BER Encoding Data Types
	public static byte BOOLEAN = 0x01;
	public static byte INTEGER_TYPE = 0x02;
	public static byte BIT_STRING = 0x03;
	public static byte STRING_OCTET = 0x04;
	public static byte NULL_VALUE = 0x05;
	public static byte OBJECT_IDENTIFIER = 0x06;
	public static byte SEQUENCE = 0x30;

	//PDU types
	public static int GET_REQUEST = 0xA0;
	public static int GETNEXT_REQUEST = 0xA1;
	public static int GETRESPONSE = 0xA2;
	public static int SET_REQUEST = 0xA3;
	public static int TRAP = 0xA4;

	public static String MANAGER = "manager";
	public static String AGENT = "agent";

	//Error Constants
	public static int NO_ERROR = 0;
	public static int TOO_BIG_ERROR = 1;
	public static int NO_SUCHNAME_ERROR = 2;
	public static int BAD_VALUE_ERROR = 2;
}
