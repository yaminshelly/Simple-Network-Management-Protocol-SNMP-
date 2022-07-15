package source.com.snmp;

import java.util.*;
import java.net.*;
import java.util.logging.*;

import javax.xml.bind.DatatypeConverter;

public class SNMPUtils
{

	private static Logger logger = Logger.getLogger(SNMPUtils.class.getName());	
	/*Add a ASN1 encoding Header for 
		SNMP Message */
	public static byte[] constructSNMPPacket(byte data[])
	{
		/*ASN BER Encoding Header
		  SEQUENCE Message Header for overall SNMP Message */ 
		byte result_data[] = new byte[2+data.length];
		result_data[0] = SNMPConstants.SEQUENCE;
		result_data[1] = (byte)data.length;

		System.arraycopy(data, 0, result_data, 2, data.length);
		
		return result_data;
	}
	
	/*Adding SNMPMessage Header version, Community String
		over SNMP PDU Message */
	public static byte[] constructSNMPMessgae(byte data[], byte ver)
	{
		
		/*version Header for SNMP
		   Supported version 1 */
		int versionlen = 1;
		byte version[] = new byte[2+versionlen];
		version[0] = SNMPConstants.INTEGER_TYPE;
		version[1] = 0x01; //Length;
		version[2] = ver; //version
		
		/* Community String of String SNMP Packet
		   Its like password if its mismatch, agent will discard ur message */
		String community_str = new String("PRIVATE");
		byte[] comm_tobytes = community_str.getBytes();
		byte community[] = new byte[2+comm_tobytes.length];
		community[0] = SNMPConstants.STRING_OCTET;
		community[1] = (byte)comm_tobytes.length;
		System.arraycopy(comm_tobytes, 0, community, 2, comm_tobytes.length);
		
		/* Resultant SNMP Packet with
		   Version and community String Added */
		byte message[] = new byte[version.length+community.length+data.length];
		System.arraycopy(version, 0, message, 0, version.length);
		System.arraycopy(community, 0, message, version.length, community.length);
		System.arraycopy(data, 0, message, version.length+community.length, data.length);

		return message;
	}
	
	/* ASN 1 BER Encoding for 
		Object Identifier Data */
	public static byte[] encodeOID(String data)
	{
		String[] bytes = data.split("\\.");	// Split input OID based on '.'

		// Count the no. of big numbers in OID (i.e above 127)
		int big_number_count = 0;
		for (int i = 0; i < bytes.length; i++)
			if(Integer.decode(bytes[i]) > 127) // less than 0 condition not required
				big_number_count ++;
		
		int oid_length = bytes.length - 1 + big_number_count; 
		byte oid[] = new byte[oid_length];

		// Parse Initial 2 bytes to encode the first number of OID according to BER [Basic Encoding Rule]
		int x = Integer.parseInt(bytes[0]); 
		int y = Integer.parseInt(bytes[1]);
		int first_byte = 40 * x + y;

		// Convert the first number to HEX
		String first_byte_hex = Integer.toHexString(first_byte); 
		oid[0] = Integer.decode("0x"+first_byte_hex).byteValue();

		// Store the remaining numbers in OID in byte format
		for(int i = 0,j = 0; i < oid.length && j < bytes.length - 2; i++)
			// Encode big numbers according to BER if above 127
			if(Integer.decode(bytes[2 + j]) > 127)
			{
				/*
				 * If a number in OID is 1002,  then it is encoded as 0x87 and 0x6A
				 * The first octet (first byte) is obtained by right shifting the number by 0x07 and ORing the result with 0x80
				 * The second octet (second byte) is obtained by ANDing the number with 0x7F
				 */
				// Counters: i -> oid array and j -> byte array (excluding the first 2 elements)
				oid[1 + i] = Integer.decode("0x" + Integer.toHexString(((Integer.decode(bytes[2 + j]) >> 0x07 )| 0x80))).byteValue(); //First byte
				oid[1 + (i++) + 1] = Integer.decode("0x" + Integer.toHexString(Integer.decode(bytes[2 + (j++)]) & 0x7F)).byteValue();	// Second byte
				// i and j is incremented within the array index 
			}
			else
				oid[1 + i] = Integer.decode(bytes[2 + (j++)]).byteValue();
	
		return oid;	
	} 
	
	/* ASN1 Object Identifier
	   BER based decoding */	
	public static String decodeOID(byte oid_data[])
	{
		int subidentifier;
		int length;

		length = oid_data.length;

		int[] oid = new int[length+2];	
		int pos = 1;
		int j=0;
		while (length > 0){
			subidentifier = 0;
			int b;
			do {
				int encoded_byte = oid_data[j];
				
				/* OID Decode if most significant bit set it indicates the decimal value 
					denoted in 2 bytes, if not it denoted in 1 byte */
	
				b = encoded_byte & 0xFF;
				
				/* if it has 8 and more bits, the value is "spread" into multiple octets - split the binary representation into 7 bit chunks (from right), 
				left-pad the first one with zeroes if needed, and form octets from these septets by adding most significant (left) bit 1, 
				except from the last chunk, which will have bit 0 there.
				*/

				subidentifier = (subidentifier << 7) + (b & ~(0x80));
				length--;
				j++;
			} while ((length > 0) && ((b & 0x80) != 0));	/* last byte has high bit clear */
			oid[pos++] = subidentifier;
		}
		
		/*Hence first 2 bytes of OID are
			encoded into 40*x+y
			based on this */
		subidentifier = oid[1];
		if (subidentifier == 0x2B){
			oid[0] = 1;
			oid[1] = 3;
		}
		else if (subidentifier >= 0 && subidentifier < 80) {
			if (subidentifier < 40) {
				oid[0] = 0;
				oid[1] = subidentifier;
			}
			else {
				oid[0] = 1;
				oid[1] = subidentifier - 40;
			}
		}
		else {
			oid[0] = 2;
			oid[1] = subidentifier - 80;
		}
		if (pos < 2) {
			pos = 2;
		}
		int[] value = new int[pos];
		System.arraycopy(oid, 0, value, 0, pos);
	
		/* Coverting the OID into String Format */
		StringBuffer buffer = new StringBuffer();	
		for(int i=0 ; i< value.length ; i++)
		{
			if(i == value.length - 1)
			{
				buffer.append(value[i]);
			}
			else
			{
				buffer.append(value[i]+".");
			}
		}	
		return buffer.toString();
	}		

	
	//Construct GetRequest PDU Message
	public static byte[] constructGetRequestPDUMesage(ArrayList ObjectIds, int reqid)
	{

		byte requestID[] = new byte[3];
		
		//SNMP Request ID Header
		requestID = getASN1Object(reqid); 
		
		//SNMP errorValue Header
		byte errorValue[] = new byte[3];
		errorValue[0] = SNMPConstants.INTEGER_TYPE;
		errorValue[1] = 1;
		errorValue[2] = (byte)SNMPConstants.NO_ERROR;
		
		//SNMP errorIndex Header
		byte errorIndex[] = new byte[3];
		errorIndex[0] = SNMPConstants.INTEGER_TYPE;
		errorIndex[1] = 1;
		errorIndex[2] = 0;

		/*Variable Bind List Values
	           It will be NULL in case of GetRequest*/ 
		byte var_value[] = new byte[2];
		var_value[0] = SNMPConstants.NULL_VALUE;
		var_value[1] = 0;
		
		/* VarbindList is to carry the multiple OIDS with corresponding values in ASN1 format
		 * Its an major component of the PDU packet structure */
		ArrayList varbindlist = new ArrayList();
		int totallength = 0;	
		for(int i=0 ; i< ObjectIds.size() ; i++)
		{
			String objectid = (String)ObjectIds.get(i);
			
			logger.info( "[GET REQUEST -- ][OBJECTID]["+objectid+"]");
			byte objid[] = encodeOID(objectid);

			byte object_value[] = new byte[objid.length + 2 + var_value.length];
			object_value[0] = SNMPConstants.OBJECT_IDENTIFIER;
			object_value[1] = (byte)objid.length;
			System.arraycopy(objid, 0, object_value, 2, objid.length);

			System.arraycopy(var_value, 0, object_value, 2+objid.length, var_value.length);	

			byte varbind[] = new byte[object_value.length+2];
			varbind[0] = SNMPConstants.SEQUENCE;
			varbind[1] = (byte)object_value.length;
			System.arraycopy(object_value, 0, varbind, 2, object_value.length);	

			varbindlist.add(varbind);

			totallength = totallength + varbind.length;	
		}
		

		byte varbind_list[] = new byte[2+totallength];
		varbind_list[0] = SNMPConstants.SEQUENCE;
		varbind_list[1] = (byte)totallength;
		
		/*Add the Total Bytes of all variableBind values and
		  form a ASN1 Sequnce Header over the Data */
		int pos = 2;
		for(int i=0; i<varbindlist.size(); i++)
		{
			byte varbind_value[] = (byte[]) varbindlist.get(i);
				
			System.arraycopy(varbind_value, 0, varbind_list, pos, varbind_value.length);
			pos = pos + varbind_value.length;
		} 	

		byte snmpGetRequest[] = new byte[2+requestID.length+errorValue.length+errorIndex.length+varbind_list.length];
		
		//SNMP MESSAGE TYPE REQ HEADER
		snmpGetRequest[0] = (byte)SNMPConstants.GET_REQUEST;
		snmpGetRequest[1] = (byte)(snmpGetRequest.length - 2);

		pos = 2;
		System.arraycopy(requestID, 0, snmpGetRequest, pos, requestID.length);
		pos = pos+requestID.length;
		System.arraycopy(errorValue, 0, snmpGetRequest, pos, errorValue.length);
		pos = pos+errorValue.length;
		System.arraycopy(errorIndex, 0, snmpGetRequest, pos, errorIndex.length);
		pos = pos + errorIndex.length;
		System.arraycopy(varbind_list, 0, snmpGetRequest, pos, varbind_list.length);

		return snmpGetRequest; 

	}
	
	/* Build a GetNextRequest PDU
		Message */	
	public static byte[] getNextRequestPDU(ArrayList ObjectIds, SNMPInfo info)
	{
		long reqid = info.getReqid();
		
		/*Request ID indicates the unique ID of Request.. to correlate the request and response
		   If Response comes with the different ReqID for this getRequest
			the packet will be discarded */

		byte requestID[] = getASN1Object(reqid);	

                /*requestID[0] = SNMPConstants.INTEGER_TYPE;
                requestID[1] = 1;
                requestID[2] = 1; */

                byte errorValue[] = new byte[3];
                errorValue[0] = SNMPConstants.INTEGER_TYPE;
                errorValue[1] = 1;
                errorValue[2] = (byte)SNMPConstants.NO_ERROR;

                byte errorIndex[] = new byte[3];
                errorIndex[0] = SNMPConstants.INTEGER_TYPE;
                errorIndex[1] = 1;
                errorIndex[2] = 0;

                //value
                byte var_value[] = new byte[2];
                var_value[0] = SNMPConstants.NULL_VALUE;
                var_value[1] = 0;
		
		/* VarbindList is to carry the multiple OIDS with corresponding values in ASN1 format
                 * Its an major component of the PDU packet structure */
              	ArrayList varbindlist = new ArrayList();
                int totallength = 0;
                for(int i=0 ; i< ObjectIds.size() ; i++)
                {
                        String objectid = (String)ObjectIds.get(i);

                        logger.info( "[GET NEXT REQUEST -- ][OBJECT ID]["+objectid+"]");
                        byte objid[] = encodeOID(objectid);

                        byte object_value[] = new byte[objid.length + 2 + var_value.length];
                        object_value[0] = SNMPConstants.OBJECT_IDENTIFIER;
                        object_value[1] = (byte)objid.length;
                        System.arraycopy(objid, 0, object_value, 2, objid.length);

                        System.arraycopy(var_value, 0, object_value, 2+objid.length, var_value.length);

                        byte varbind[] = new byte[object_value.length+2];
                        varbind[0] = SNMPConstants.SEQUENCE;
                        varbind[1] = (byte)object_value.length;
                        System.arraycopy(object_value, 0, varbind, 2, object_value.length);

                        varbindlist.add(varbind);

                        totallength = totallength + varbind.length;
                }
 

                byte varbind_list[] = new byte[2+totallength];
		
		varbind_list[0] = SNMPConstants.SEQUENCE;
                varbind_list[1] = (byte)totallength;
		
		/*Add the Total Bytes of all variableBind values and
                  form a ASN1 Sequnce Header over the Data */
                int pos = 2;
                for(int i=0; i<varbindlist.size(); i++)
                {
                        byte varbind_value[] = (byte[]) varbindlist.get(i);

                        System.arraycopy(varbind_value, 0, varbind_list, pos, varbind_value.length);
                        pos = pos + varbind_value.length;
                }
			

                byte snmpGetNextRequest[] = new byte[2+requestID.length+errorValue.length+errorIndex.length+varbind_list.length];
	
		//SNMP GET NEXT REQUEST HEADER
                snmpGetNextRequest[0] = (byte)SNMPConstants.GETNEXT_REQUEST;
                snmpGetNextRequest[1] = (byte)(snmpGetNextRequest.length -2);

                pos = 2;
                System.arraycopy(requestID, 0, snmpGetNextRequest, pos, requestID.length);
                pos = pos+requestID.length;
                System.arraycopy(errorValue, 0, snmpGetNextRequest, pos, errorValue.length);
                pos = pos+errorValue.length;
                System.arraycopy(errorIndex, 0, snmpGetNextRequest, pos, errorIndex.length);
                pos = pos + errorIndex.length;
                System.arraycopy(varbind_list, 0, snmpGetNextRequest, pos, varbind_list.length);

                return snmpGetNextRequest;

	}
	
	/*Construct a GetResponsePDU Message for the corresponding OIDs
		recvd in getRequest SNMPMessage */	
	public static byte[] constructGetResponsePDU(SNMPInfo info)
	{
		byte requestID[];

		//Get ASN based byte notation For Integer Data 
		requestID = getASN1Object(info.getReqid());		
		

                byte errorValue[] = new byte[3];
                errorValue[0] = SNMPConstants.INTEGER_TYPE;
                errorValue[1] = 1;
                errorValue[2] = (byte)info.getErrorValue();

                byte errorIndex[] = new byte[3];
                errorIndex[0] = SNMPConstants.INTEGER_TYPE;
                errorIndex[1] = 1;
                errorIndex[2] = (byte)info.getErrorIndex();
		
		HashMap objectid_valueMap = info.getMIBValueMap();	
		int totallength = 0;
		ArrayList varbindlist = new ArrayList();
		for (Object object : objectid_valueMap.keySet())
		{
			String objectid = (String)object;
				
			String value = (String)objectid_valueMap.get(objectid);		     		
			
			logger.info( "[GET RESPONSE -- ][OBJECT ID]["+objectid+"][VALUE]["+value+"]");	
			byte objid[] = encodeOID(objectid);
                        
                        byte object_Identifier[] = new byte[objid.length + 2];
                        object_Identifier[0] = SNMPConstants.OBJECT_IDENTIFIER;
                        object_Identifier[1] = (byte)objid.length;
                        System.arraycopy(objid, 0, object_Identifier, 2, objid.length);	
			
			//byte object_value[] = value.getBytes();
			//byte OID_value[] = new byte[2+object_value.length];
			byte OID_value[] = getASN1Object(value); 
			//OID_value[0] = SNMPConstants.STRING_OCTET;
			//OID_value[1] = (byte)object_value.length;
			//System.arraycopy(object_value, 0, OID_value, 2, object_value.length);

			byte varbind[] = new byte[object_Identifier.length+OID_value.length+2];
                        varbind[0] = SNMPConstants.SEQUENCE;
                        varbind[1] = (byte)(object_Identifier.length + OID_value.length);
                        System.arraycopy(object_Identifier, 0, varbind, 2, object_Identifier.length);
			System.arraycopy(OID_value, 0, varbind, object_Identifier.length+2, OID_value.length);
			
			totallength = totallength + varbind.length;
			varbindlist.add(varbind); 
		}
		
		byte varbind_list[] = new byte[2+totallength];
                varbind_list[0] = SNMPConstants.SEQUENCE;
                varbind_list[1] = (byte)totallength;

                int pos = 2;
                for(int i=0; i<varbindlist.size(); i++)
                {       
                        byte varbind_value[] = (byte[]) varbindlist.get(i);
                         
                        System.arraycopy(varbind_value, 0, varbind_list, pos, varbind_value.length);
                        pos = pos + varbind_value.length;
                } 

                byte snmpGetResponse[] = new byte[2+requestID.length+errorValue.length+errorIndex.length+varbind_list.length];

                //SNMP MESSAGE TYPE REQ HEADER
                snmpGetResponse[0] = (byte)SNMPConstants.GETRESPONSE;
                snmpGetResponse[1] = (byte)(snmpGetResponse.length - 2);

                pos = 2;
                System.arraycopy(requestID, 0, snmpGetResponse, pos, requestID.length);
                pos = pos+requestID.length;
                System.arraycopy(errorValue, 0, snmpGetResponse, pos, errorValue.length);
                pos = pos+errorValue.length;
                System.arraycopy(errorIndex, 0, snmpGetResponse, pos, errorIndex.length);
                pos = pos + errorIndex.length;
                System.arraycopy(varbind_list, 0, snmpGetResponse, pos, varbind_list.length);

                return snmpGetResponse;			
		
	}
		
	public static byte[] constructSetRequestPDU(SNMPInfo info)
	{ 	
		long reqid = info.getReqid();
                byte requestID[] = getASN1Object(reqid);
                logger.info( " SET REq Id "+DatatypeConverter.printHexBinary(requestID));
		
		byte errorValue[] = new byte[3];
                errorValue[0] = SNMPConstants.INTEGER_TYPE;
                errorValue[1] = 1;
                errorValue[2] = (byte)SNMPConstants.NO_ERROR;

                byte errorIndex[] = new byte[3];
                errorIndex[0] = SNMPConstants.INTEGER_TYPE;
                errorIndex[1] = 1;
                errorIndex[2] = 0;
		
		int totallength = 0;
		HashMap mibOID_valueMap = info.getMIBValueMap();
                ArrayList varbindlist = new ArrayList();
                for (Object object : mibOID_valueMap.keySet())
                {
                        String objectid = (String)object;
                        String value = (String)mibOID_valueMap.get(objectid);
			
			logger.info( "[SET REQUEST -- ][OBJECT ID]["+objectid+"][VALUE]["+value+"]");
                        byte objid[] = encodeOID(objectid);

                        byte object_Identifier[] = new byte[objid.length + 2];
                        object_Identifier[0] = SNMPConstants.OBJECT_IDENTIFIER;
                        object_Identifier[1] = (byte)objid.length;
                        System.arraycopy(objid, 0, object_Identifier, 2, objid.length);

                        byte OID_value[] = getASN1Object(value); 

                        byte varbind[] = new byte[object_Identifier.length+OID_value.length+2];
                        varbind[0] = SNMPConstants.SEQUENCE;
                        varbind[1] = (byte)(object_Identifier.length + OID_value.length);
                        System.arraycopy(object_Identifier, 0, varbind, 2, object_Identifier.length);
                        System.arraycopy(OID_value, 0, varbind, object_Identifier.length+2, OID_value.length);

                        totallength = totallength + varbind.length;
                        varbindlist.add(varbind);
                }
		
		byte varbind_list[] = new byte[2+totallength];
                varbind_list[0] = SNMPConstants.SEQUENCE;
                varbind_list[1] = (byte)totallength;

                int pos = 2;
                for(int i=0; i<varbindlist.size(); i++)
                {
                        byte varbind_value[] = (byte[]) varbindlist.get(i);

                        System.arraycopy(varbind_value, 0, varbind_list, pos, varbind_value.length);
                        pos = pos + varbind_value.length;
                } 

                byte snmpSetRequest[] = new byte[2+requestID.length+errorValue.length+errorIndex.length+varbind_list.length];

                //SNMP MESSAGE TYPE REQ HEADER
                snmpSetRequest[0] = (byte)SNMPConstants.SET_REQUEST;
                snmpSetRequest[1] = (byte)(snmpSetRequest.length - 2);

                pos = 2;
                System.arraycopy(requestID, 0,snmpSetRequest, pos, requestID.length);
                pos = pos+requestID.length;
                System.arraycopy(errorValue, 0,snmpSetRequest, pos, errorValue.length);
                pos = pos+errorValue.length;
                System.arraycopy(errorIndex, 0,snmpSetRequest, pos, errorIndex.length);
                pos = pos + errorIndex.length;
                System.arraycopy(varbind_list, 0,snmpSetRequest, pos, varbind_list.length);

                return snmpSetRequest;		
					
	}   

	/* Trap Message that which agent notifies SNMP Manager
		regarding down of any monitoring Object */	
	public static byte[] getTrapMessage(SNMPInfo message)
	{
		try
		{
			String enterprise_oid = message.getEnterPriseOID();
			byte oid_bytes[] = enterprise_oid.getBytes();
			byte enterprise[] = new byte[oid_bytes.length+2];
			enterprise[0] = SNMPConstants.OBJECT_IDENTIFIER;
			enterprise[1] = (byte)oid_bytes.length;
			System.arraycopy(oid_bytes, 0, enterprise, 2, oid_bytes.length);
			
			/*Trap Message Agent Address to detect
			    which specific agent is down */
			byte agent_addr[] = new byte[6];
			agent_addr[0] = 0x40;
			agent_addr[1] = 0x04;

			InetAddress ia = InetAddress.getLocalHost();
			byte[] ip_in_bytes = ia.getAddress();
			System.arraycopy(ip_in_bytes, 0,  agent_addr, 2, ip_in_bytes.length);
			
			/* Generic Trap Message indicates
			    the type of failure */
			byte[] generic_trap = new byte[3];
			generic_trap[0] = SNMPConstants.INTEGER_TYPE;
			generic_trap[1] = 1;
			generic_trap[2] = 6; //enterprise Type
			
			/* Enterprise Level Trap 
			    Indication */
			byte[] specific_trap = new byte[3];
			specific_trap[0] = SNMPConstants.INTEGER_TYPE;
			specific_trap[1] = 1;
			specific_trap[1] = 1;

			byte[] time_elaspsed = new byte[4];
			time_elaspsed[0] = (byte)0x43;
			time_elaspsed[1] = (byte)0x02;	
			
	
			int totallength = 0;
			HashMap mibOID_valueMap = message.getMIBValueMap();
			ArrayList varbindlist = new ArrayList();
			for (Object object : mibOID_valueMap.keySet())
			{       
				String objectid = (String)object;
				String value = (String)mibOID_valueMap.get(objectid);

				logger.info( "[TRAP REQUEST -- ][OBJECT ID]["+objectid+"][VALUE]["+value+"]");
				byte objid[] = encodeOID(objectid);

				byte object_Identifier[] = new byte[objid.length + 2];
				object_Identifier[0] = SNMPConstants.OBJECT_IDENTIFIER;
				object_Identifier[1] = (byte)objid.length;
				System.arraycopy(objid, 0, object_Identifier, 2, objid.length);

				byte OID_value[] = getASN1Object(value);

				byte varbind[] = new byte[object_Identifier.length+OID_value.length+2];
				varbind[0] = SNMPConstants.SEQUENCE;
				varbind[1] = (byte)(object_Identifier.length + OID_value.length);
				System.arraycopy(object_Identifier, 0, varbind, 2, object_Identifier.length);
				System.arraycopy(OID_value, 0, varbind, object_Identifier.length+2, OID_value.length);

				totallength = totallength + varbind.length;
				varbindlist.add(varbind);
			}

			byte varbind_list[] = new byte[2+totallength];
			varbind_list[0] = SNMPConstants.SEQUENCE;
			varbind_list[1] = (byte)totallength;

                	int pos = 2;
                	for(int i=0; i<varbindlist.size(); i++)
                	{
                        	byte varbind_value[] = (byte[]) varbindlist.get(i);

                        	System.arraycopy(varbind_value, 0, varbind_list, pos, varbind_value.length);
                        	pos = pos + varbind_value.length;
                	}
	
	
			byte trap_data[] = new byte[enterprise.length+agent_addr.length+generic_trap.length+specific_trap.length+time_elaspsed.length+varbind_list.length+2];
			trap_data[0] = (byte)SNMPConstants.TRAP;
			trap_data[1] = (byte)trap_data.length;

			pos = 2;
			System.arraycopy(enterprise, 0, trap_data, pos, enterprise.length);

			pos = pos+enterprise.length;
			System.arraycopy(agent_addr, 0, trap_data, pos, agent_addr.length);
			pos = pos +agent_addr.length;
			System.arraycopy(generic_trap, 0, trap_data, pos, generic_trap.length);
			pos = pos + generic_trap.length;
			System.arraycopy(specific_trap, 0, trap_data, pos, specific_trap.length);
			pos = pos + specific_trap.length;
			System.arraycopy(time_elaspsed,0, trap_data, pos, time_elaspsed.length);
			pos = pos + time_elaspsed.length;
			System.arraycopy(varbind_list, 0, trap_data, pos, varbind_list.length);

			return trap_data;
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}

		return null;   


	}
	
	/* Converting the Given Data into corresponding
		ASN1 BER Encoded Data */	
	public static byte[] getASN1Object(Object value)
	{
		if (value instanceof Integer)
		{	
			int obj_value = (int)value;		
			int length = getEncodeLengthofInt((long)obj_value);			
			
			int bit_shift = 8 * (length -1);
			byte int_data[] = new byte[length];
			for(int i = 0 ; i<length; i++)
			{	
				int_data[i] = (byte)(obj_value >> bit_shift);
				bit_shift = (bit_shift - 8);
			}
			
			/* ASN1 BER Encoding for Integer Data */
			byte asn_object[] = new byte[2+length];
			asn_object[0] = SNMPConstants.INTEGER_TYPE;
			asn_object[1] = (byte)length;
			System.arraycopy(int_data, 0, asn_object, 2, int_data.length);
			
			return asn_object;	
		}
		if(value instanceof Long)
		{
			long obj_value = (long)value; 
                        
                        int length = getEncodeLengthofInt((long)obj_value);
                        
                        int bit_shift = 8 * (length -1);
                        byte int_data[] = new byte[length];
                        for(int i = 0 ; i<length; i++)
                        {       
                                int_data[i] = (byte)(obj_value >> bit_shift);
                                bit_shift = (bit_shift - 8);
                        }
                       	
			/* ASN1 BER ENCODING for Integer Data */ 
                        byte asn_object[] = new byte[2+length];
                        asn_object[0] = SNMPConstants.INTEGER_TYPE;
                        asn_object[1] = (byte)length; 
                        System.arraycopy(int_data, 0, asn_object, 2, int_data.length);
                        
                        return asn_object;
		}	
  
		if (value instanceof String)
		{	
			String data = (String) value;
			byte string_data[] = data.getBytes();

			/* ASN1 BER ENCODING for String Data */
			byte res_data[] = new byte[string_data.length+2];
			res_data[0] = SNMPConstants.STRING_OCTET;
			res_data[1] = (byte)string_data.length;
			System.arraycopy(string_data, 0, res_data, 2, string_data.length);
			return res_data;
		}	
		if (value instanceof Boolean)
		{
			byte asn_data[] = new byte[3];
			asn_data[0] = SNMPConstants.BOOLEAN;
			asn_data[1] = 0x01;
			if((Boolean)value)
			{
				asn_data[2] = 0x01;
			}
			return asn_data;	  				
		}
		
		return null;	
	}
	
	/* Function to Identify the number of bytes required
		to accomodate the given decimal value */	
	public static int getEncodeLengthofInt(long temp)
	{
		int bits = 0, length = 0; 
		while (temp != 0)
		{         
			temp = temp >> 1;
			++bits;
		}         
		if(bits%8 == 0)
		{
			length = bits/8;	
		}
		else
		{
			length = (bits/8) + 1;
		}
		return length;
	}   		


}
