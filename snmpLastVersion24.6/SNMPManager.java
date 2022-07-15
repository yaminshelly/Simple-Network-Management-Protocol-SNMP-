package source.com.snmp;

import java.net.*;
import java.util.*;
import java.util.logging.*;
import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;
public class SNMPManager
{
	private static DatagramSocket socket;
	private static String COMMUNITY_STRING = "PRIVATE";
	private static Logger logger = Logger.getLogger(SNMPManager.class.getName());
	private static int reqID = 0;
	private static Object lock = new Object();

	static
        {
                try
                {
                        socket = new DatagramSocket();
                }
                catch(Exception e)
                {
                }
        }

	/*Allocate Unique RequestID for every message Sent
	*/	
	public static int getRequestID()
	{
		synchronized(lock)
		{
			return ++reqID;
		}
		
	}

	/* UDP Data Reader
	 *It will process all the SNMP Messages recvd from agent
	 */	
	public static void handleData(byte[] data)
	{	
		int snmpmessage_len = (data[1] & 0xFF);
		byte snmpmessage[] = new byte[snmpmessage_len];
		System.arraycopy(data, 2, snmpmessage, 0, snmpmessage.length);
		
		/*Version Value Parser
                 * Supported version in this application is version 1
                 */
		int pos = 0;
		if(snmpmessage[0] == SNMPConstants.INTEGER_TYPE)
		{
			int version = snmpmessage[2];
			if(version > 1)
			{
				logger.info( "[ INVALID SNMP VERSION ][VERSION]["+version+"]");
				return; 
			}
		}

		pos = pos+3; //ASN Data VERSION Length


		/*Community String Parser
                 * If Request Community String mismatches with server community String, the packet will be discarded
                 */
		byte com_str_len = snmpmessage[pos+1]; //SNMP Community String length;

		byte community_string[] = new byte[com_str_len];
		System.arraycopy(snmpmessage, pos+2, community_string, 0, community_string.length);
		String com_str = new String(community_string);
		if(!com_str.equals(COMMUNITY_STRING))
		{
			logger.info( "[INVALID COMMUNITY STRING -- ][COM_STRING]["+com_str+"]");
			return;
		}

		pos = pos + 2; //Overall data Asn Header
		pos = pos + 2 + com_str_len;

		//Extract the PDU Message
		byte PDUMessage[] = new byte[data.length - pos];
		System.arraycopy(data, pos, PDUMessage, 0, PDUMessage.length);

		int pdu_msg_type = PDUMessage[0] & 0xFF;
		if(pdu_msg_type == SNMPConstants.GETRESPONSE)
		{
			int pdu_data_len = PDUMessage[1] & 0xFF;
			byte getresponse_data[] = new byte[pdu_data_len];
			System.arraycopy(PDUMessage, 2, getresponse_data, 0, getresponse_data.length);
			processResponsePDUMessage(getresponse_data);
			logger.info( "[SNMP RESPONSE MSG RECVD -]");
		}

	}
	
	public static void processResponsePDUMessage(byte response_msg[])
	{
		//Get Request ID
                logger.info(DatatypeConverter.printHexBinary(response_msg));
                int pos = 0;
                int reqid_len = response_msg[1] & 0xFF;
                byte requestID[] = new byte[reqid_len];
                System.arraycopy(response_msg, pos+2, requestID, 0, requestID.length);
                int reqID = new BigInteger(requestID).intValue();

                pos = pos + 3;

                //ErrorValue
                int error_value_len = response_msg[pos+1] & 0xFF;
                byte error_value[] = new byte[error_value_len];
                System.arraycopy(response_msg, pos+2, error_value, 0, error_value_len);
                int value = new BigInteger(error_value).intValue(); 
		
		/* Handling of Error get From Response
		  */	
		if(value == SNMPConstants.TOO_BIG_ERROR)
		{
			logger.info(" [BAD VALUE ERROR --]");
			return;
		}
		else if(value == SNMPConstants.NO_SUCHNAME_ERROR)
		{
			logger.info( "[NO_SUCHNAME_ERROR ]");
			return;
		}
		else if(value == SNMPConstants.BAD_VALUE_ERROR)
		{
			logger.info( "[BAD VALUE ERROR ]");
			return;
		}
			

                pos = pos +2+error_value_len;

                //Error Index
                int error_index_len = response_msg[pos+1] & 0xFF;
                byte error_index[] = new byte[error_index_len];
                System.arraycopy(response_msg, pos+2, error_index, 0, error_index_len);
                int error_index_value = new BigInteger(error_index).intValue(); 

                pos = pos +2+error_index_len;

                //Varbind list
                int list_length = response_msg[pos+1] & 0xFF;
                byte varbind_list[] = new byte[list_length];

                pos = pos + 2;
                System.arraycopy(response_msg, pos, varbind_list, 0, varbind_list.length);
                logger.info(DatatypeConverter.printHexBinary(varbind_list));
		
		/* process varbindlist of Response PDU message
		 * its consists of list of varbinds
		 * Each varbind is consists of OID and retrieved Value
		 */	
		int index = 0; 
                while(index < list_length)
                {
                        int varbind_len = varbind_list[index+1] & 0xFF;
                        index = index + 2;

                        //Object Identifier
                        int obj_id_len = varbind_list[index+1] & 0xFF;

                        byte object_id[] = new byte[obj_id_len];
                        System.arraycopy(varbind_list, index+2, object_id, 0, object_id.length);

                        String objectid = SNMPUtils.decodeOID(object_id);
                        logger.info( "[GET RESPONSE RECVD --][OBJECT ID]["+objectid+"]");
			
			index = index+2+object_id.length;
			
			//Get Values
			byte type = varbind_list[index];
			if(type == SNMPConstants.STRING_OCTET)
			{
				int value_len = varbind_list[index+1] & 0xFF; 
				byte obj_value[] = new byte[value_len];
				System.arraycopy(varbind_list, index+2, obj_value, 0, obj_value.length);
				String Object_value = new String(obj_value);
				logger.info( "value -- "+Object_value);
				index = index + obj_value.length + 2;
			}
			else
			{	
                        	index = index + 2;
			}
		}	
	}
	
	/* SEND SNMP Mesage to Agent
	   Writting Data to Agent Address
	  */			
	public static void sendMessageToAgent(byte snmpdata[])
	{
		try
		{
			logger.info(DatatypeConverter.printHexBinary(snmpdata));   
			InetAddress localhost = InetAddress.getLocalHost();          
			if(ConfManager.isLocalHostTestingEnabled())
			{ 
				SNMPNetwork.writeUDPData(snmpdata, socket, localhost, ConfManager.getAgentPort());
			}
			else
			{
				InetAddress agentaddr = InetAddress.getByName(ConfManager.getAgentAddr());
				SNMPNetwork.writeUDPData(snmpdata, socket, agentaddr, ConfManager.getAgentPort());
			}
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	/*Construct SEND REQ SNMP Packet, Its made of
	 *ASN 1 Encoding notation
	 *SNMP Message Header(version, comm_string)
	 *SEND REQ PDU MESSAGE
	 */
	public static void generateSendRequestPacket(ArrayList OID)
	{
		try
		{ 	
			byte PDU_data[] = SNMPUtils.constructGetRequestPDUMesage(OID, getRequestID());
			byte snmp_message[] = SNMPUtils.constructSNMPMessgae(PDU_data, (byte)0);
			byte snmp_packet[] = SNMPUtils.constructSNMPPacket(snmp_message);
			
			sendMessageToAgent(snmp_packet);			
			/*logger.info(DatatypeConverter.printHexBinary(snmp_packet));
			InetAddress localhost = InetAddress.getLocalHost();		
			SNMPNetwork.writeUDPData(snmp_packet, socket, localhost, ConfManager.getAgentPort());*/

			logger.info( " GET REQUEST SNMP PACKET SEND ");	    
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}	
		
	}
	
	/*Construct SEND NEXT REQ SNMP Packet, Its made of
         *ASN 1 Encoding notation
         *SNMP Message Header(version, comm_string)
         *SEND Next REQ PDU MESSAGE with OID varbind List
         */	
	public static void generateGetNextRequestPacket(ArrayList OID)
	{
		SNMPInfo info = new SNMPInfo();
		info.setReqID(getRequestID());
		byte PDU_data[] = SNMPUtils.getNextRequestPDU(OID, info);
		byte snmp_message[] = SNMPUtils.constructSNMPMessgae(PDU_data, (byte)0);
		byte snmp_packet[] = SNMPUtils.constructSNMPPacket(snmp_message);
		
		sendMessageToAgent(snmp_packet);
		
		logger.info("[ SENT GET NEXT REQUEST SNMP PACKET -- ]");
	}

	/*Construct SEND SET REQ SNMP Packet, Its made of
         *ASN 1 Encoding notation
         *SNMP Message Header(version, comm_string)
         *SEND SET REQ PDU MESSAGE with OID varbind List
         */	
	public static void generateSetRequest(HashMap OID_ValueMap)
	{
		SNMPInfo info = new SNMPInfo();
                info.setReqID(getRequestID());
		info.setMIBValueMap(OID_ValueMap);
		
		byte PDU_data[] = SNMPUtils.constructSetRequestPDU(info);	
		byte snmp_message[] = SNMPUtils.constructSNMPMessgae(PDU_data, (byte)0);
                byte snmp_packet[] = SNMPUtils.constructSNMPPacket(snmp_message);	
		
		sendMessageToAgent(snmp_packet);
		
		logger.info("[ SENT SET REQUEST SNMP PACKET -- ]");	
	} 	
			 	

	public static void main(String args[])
	{
		try
                {
			String work_dir = System.getProperty("user.dir");
			System.setProperty("server.home", work_dir);
			
			ConfManager.loadConfFile();
                        SNMPNetwork network = new SNMPNetwork();
			
			//Intialize server and bind socket on port 161
			network.initializeSocket(ConfManager.getManagerPort());
			network.setSNMPType("manager");
		
                        Thread thread = new Thread(network);
                        thread.setName("UDPNETWORK"); //No I18N
                        thread.start();
			
			ArrayList oid = new ArrayList();
			oid.add("1.3.4.234.1.8.7");	
			generateSendRequestPacket(oid);
			
			ArrayList list = new ArrayList();
                        list.add("1.3.4.234.1.8"); //OID 
			
			logger.info ( "[SEND NEXT REQUEST PDU -- ]");			
			generateGetNextRequestPacket(list);

			HashMap oid_valueMap = new HashMap();
			oid_valueMap.put("1.3.4.234.1.8.7" , "80MB");

	
			generateSetRequest(oid_valueMap);
			
			generateSendRequestPacket(oid);
			
			/* Command Line User Interface OPtions
			 * to Send Mnd test multiple types of Request
			 */ 	
			while(true)
			{
				Thread.sleep(500);
				logger.info( "Plz Enter the option -- ");	
				logger.info( "1.GetRequest --");
				logger.info( "2.GetNextRequest --");
				logger.info( "3.Set Request -- "); 
				logger.info( "4.exit -- ");	
				
				Scanner in = new Scanner(System.in);
				int a = in.nextInt();
				if(a == 1)
				{
					logger.info(" enter the number of OIDS in Get Request");
					int oid_count = in.nextInt();
					ArrayList OID_list = new ArrayList();
					for(int i=0; i< oid_count; i++)
					{
						logger.info( "Enter the OID ");
						Scanner in1 = new Scanner(System.in);
						String s = in1.nextLine();
						OID_list.add(s);	
					}
					generateSendRequestPacket(OID_list);
				}
                                else if(a==2)
                                {
					logger.info(" enter the number of OIDS in Get Next Request");
                                        int oid_count = in.nextInt();
                                        ArrayList OID_list = new ArrayList();
                                        for(int i=0; i< oid_count; i++)
                                        {
                                                logger.info( "Enter the OID ");
                                                Scanner in1 = new Scanner(System.in);
                                                String s = in1.nextLine();
                                                OID_list.add(s);
                                        }
                                      	generateGetNextRequestPacket(OID_list); 
                                }
                                else if(a==3)
                                {
					logger.info(" enter the number of OIDS in Set Request");
					int oid_count = in.nextInt();
                                        HashMap OID_map = new HashMap();
                                        for(int i=0; i< oid_count; i++)
                                        {
                                                logger.info( "Enter the OID ");
                                                Scanner in1 = new Scanner(System.in);
                                                String s = in1.nextLine();
						logger.info( "Enter the OID value -- ");
						String oid_value = in1.nextLine(); 
                          			OID_map.put(s, oid_value);
                                        }
					generateSetRequest(OID_map);
		
                                }
				else
				{
					break;
				}
			}	

		
                } 
                catch(Exception e)
                {
			e.printStackTrace();
                }
			
				
	}
	
}
