package source.com.snmp;

import java.net.*;
import java.math.BigInteger;
import java.util.*;
import java.util.logging.*;

import javax.xml.bind.DatatypeConverter;
public class SNMPAgent
{
	private static Logger logger = Logger.getLogger(SNMPAgent.class.getName());
	private static DatagramSocket socket;	
	private static String COMMUNITY_STRING = "PRIVATE";
	private static DatagramSocket serverSocket;
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
 
	public static void handleData(byte data[], String remoteip, int remoteport)
	{
		try
		{
			logger.info( "[SNMP DATA RECVD][LENGTH]["+data.length+"]");

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
					logger.info( "INVALID SNMP VERSION ");
					return;
				}
			}

			pos = pos+3; //ASN Data VERSION Length

			byte com_str_len = snmpmessage[pos+1]; //SNMP Community String length;
			
			/*Community String Parser
			 * If Request Community String mismatches with server community String, the packet will be discarded
			*/   
			byte community_string[] = new byte[com_str_len];
			System.arraycopy(snmpmessage, pos+2, community_string, 0, community_string.length);
			String com_str = new String(community_string);
			if(!com_str.equals(COMMUNITY_STRING))
			{
				logger.info( "[INVALID COMMUNITY STRING -- ]");
				return;
			}
			
			pos = pos + 2; //Overall data Asn Header 
			pos = pos + 2 + com_str_len;

			//Extract the PDU Message
			byte PDUMessage[] = new byte[data.length - pos];
			System.arraycopy(data, pos, PDUMessage, 0, PDUMessage.length);
			
			/* process Different Types of PDU Message Recvd
			   in the Agent. */
			int pdu_msg_type = PDUMessage[0] & 0xFF;
			if(pdu_msg_type == SNMPConstants.GET_REQUEST)
			{
				logger.info( " GET Request ");
				int pdu_data_len = PDUMessage[1] & 0xFF;
				byte getreq_data[] = new byte[pdu_data_len];
				System.arraycopy(PDUMessage, 2, getreq_data, 0, getreq_data.length);
				handleGetRequestPDUMessage(getreq_data, remoteip, remoteport);
			}
			else if(pdu_msg_type == SNMPConstants.GETNEXT_REQUEST)
			{
				logger.info("[ RECVD GET NEXT REQUEST ]");
				int pdu_data_len = PDUMessage[1] & 0xFF;
                                byte getnextreq_data[] = new byte[pdu_data_len];
                                System.arraycopy(PDUMessage, 2, getnextreq_data, 0, getnextreq_data.length); 
				processGetNextRequestPDUMessage(getnextreq_data, remoteip, remoteport);
					
			}
			else if(pdu_msg_type ==  SNMPConstants.SET_REQUEST)
			{
				logger.info("[ RECVD SET REQUEST ]");
                                int pdu_data_len = PDUMessage[1] & 0xFF;
                                byte setreq_data[] = new byte[pdu_data_len];
                                System.arraycopy(PDUMessage, 2, setreq_data, 0, setreq_data.length);
                                processSetRequestPDUMessage(setreq_data, remoteip, remoteport);
				
			}	

		}
		catch(Exception e)
		{
			e.printStackTrace();
		}	

	}
	
	// Parsing and Process the Get Request PDU Message	
	public static void handleGetRequestPDUMessage(byte getReqMessage[], String remoteip, int remoteport)
	{
		//Get Request ID
		logger.info(DatatypeConverter.printHexBinary(getReqMessage));
		int pos = 0;
		int reqid_len = getReqMessage[1] & 0xFF;
		
		/* ReqID is used to track specific Request and Response
		   In this case if response sent with different ReqID
		   Packets will be discarded in Manager End */

		byte requestID[] = new byte[reqid_len];
		System.arraycopy(getReqMessage, pos+2, requestID, 0, requestID.length);
                BigInteger reqID = new BigInteger(requestID);	
		logger.info("[REQUEST ID]["+reqID.longValue()+"]");

		pos = pos + 2 +reqid_len;
		
		//ErrorValue indicates if there is any error regarding OID 
		int error_value_len = getReqMessage[pos+1] & 0xFF;
		byte error_value[] = new byte[error_value_len];
		System.arraycopy(getReqMessage, pos+2, error_value, 0, error_value_len);
		int value = new BigInteger(error_value).intValue();	
		
		pos = pos +2+error_value_len;
		
		//Error	Index
		int error_index_len = getReqMessage[pos+1] & 0xFF;
                byte error_index[] = new byte[error_index_len];
                System.arraycopy(getReqMessage, pos+2, error_index, 0, error_index_len);
                int error_index_value = new BigInteger(error_index).intValue(); 
		
		pos = pos +2+error_index_len;
		
		//Varbind list
		int list_length = getReqMessage[pos+1] & 0xFF;
		byte varbind_list[] = new byte[list_length];
		
		pos = pos + 2;
		System.arraycopy(getReqMessage, pos, varbind_list, 0, varbind_list.length);
		logger.info(DatatypeConverter.printHexBinary(varbind_list)); 
	
		/*Parsing and processing the Varbind List
		  *varbind list will contains list varbind..
		  *Varbind consists of pair of OID and associated value in ASN1 notation*/	
		int index = 0;
		HashMap mib_map = new HashMap();
		int errorcode =0;	
		while(index < list_length)
		{
			int varbind_len = varbind_list[index+1] & 0xFF;
			index = index + 2;
			
			//Object Identifier
			int obj_id_len = varbind_list[index+1] & 0xFF;
		
			byte object_id[] = new byte[obj_id_len];
			System.arraycopy(varbind_list, index+2, object_id, 0, object_id.length);
			
			String objectid = SNMPUtils.decodeOID(object_id);
			logger.info( "[GET REQUEST RECVD --][OBJECT ID]["+objectid+"]");
				
			index = index + 2 + object_id.length + 2;	
			
			String object_value = ""+MIBManager.getObjectIDValue(objectid);
			
			/* If the ObjectID got in Request is Unknown Value
			   SEND ERROR Message indicates NO SUCH NAME */
			if(object_value.equals("null"))
			{
				errorcode = SNMPConstants.NO_SUCHNAME_ERROR;
				//object_value = "-";
			} 
			 
			mib_map.put(objectid, object_value);
			
		}
		
		SNMPInfo info = new SNMPInfo();
		info.setMIBValueMap(mib_map);
		info.setReqID(reqID.longValue());
		info.setVersion(0);
		info.setErrorValue(errorcode);
		info.setErrorIndex(0); 
			
		generateGetResponsePDU(info, remoteip, remoteport);	
			
	}
	
	public static void processGetNextRequestPDUMessage(byte getNextReqMessage[], String remoteip, int remoteport)
	{
		//Get Request ID
                logger.info(DatatypeConverter.printHexBinary(getNextReqMessage));
                int pos = 0;
                int reqid_len = getNextReqMessage[1] & 0xFF;
                byte requestID[] = new byte[reqid_len];	
                System.arraycopy(getNextReqMessage, pos+2, requestID, 0, requestID.length);
              	BigInteger reqID = new BigInteger(requestID); 
		//int long = re 

                pos = pos + 2+ reqid_len;

                //ErrorValue
                int error_value_len = getNextReqMessage[pos+1] & 0xFF;
                byte error_value[] = new byte[error_value_len];
                System.arraycopy(getNextReqMessage, pos+2, error_value, 0, error_value_len);
                int value = new BigInteger(error_value).intValue(); 

                pos = pos +2+error_value_len;

                //Error Index
                int error_index_len = getNextReqMessage[pos+1] & 0xFF;
                byte error_index[] = new byte[error_index_len];
                System.arraycopy(getNextReqMessage, pos+2, error_index, 0, error_index_len);
                int error_index_value = new BigInteger(error_index).intValue(); 

                pos = pos +2+error_index_len;

                //Varbind list
                int list_length = getNextReqMessage[pos+1] & 0xFF;
                byte varbind_list[] = new byte[list_length];

                pos = pos + 2;
                System.arraycopy(getNextReqMessage, pos, varbind_list, 0, varbind_list.length);
                logger.info(DatatypeConverter.printHexBinary(varbind_list));
		
		 /*Parsing and processing the Varbind List
                  *varbind list will contains list varbind..
                  *Varbind consists of pair of OID and associated value in ASN1 notation*/	
		int index = 0;
                HashMap mib_map = new HashMap();
		int errorvalue = 0; 
                while(index < list_length)
                {       
                        int varbind_len = varbind_list[index+1] & 0xFF;
                        index = index + 2;
                        
                        //Object Identifier
                        int obj_id_len = varbind_list[index+1] & 0xFF;
                        
                        byte object_id[] = new byte[obj_id_len];
                        System.arraycopy(varbind_list, index+2, object_id, 0, object_id.length);
                        
                        String objectid = SNMPUtils.decodeOID(object_id);

			/*Get Lexigrophically Next node as per 
				GetNext Request Logic */
			String next_objectid = (String)MIBManager.getLexigrophicalNextNode(objectid);
			
			if(next_objectid == null)
			{
				errorvalue = SNMPConstants.NO_SUCHNAME_ERROR; 
			}
			else
			{
				objectid = next_objectid;
			}
  
                        logger.info( "[GET NEXT REQUEST RECVD --][OBJECT ID]["+objectid+"]");
                                
                        index = index + 2 + object_id.length + 2;
                        
                        String object_value = ""+MIBManager.getObjectIDValue(objectid);
                         
                        mib_map.put(objectid, object_value);
                 
                }
		
		SNMPInfo info = new SNMPInfo();
                info.setMIBValueMap(mib_map);
                info.setReqID(reqID.longValue());
                info.setVersion(0);
                info.setErrorValue(errorvalue);
                info.setErrorIndex(0);

                generateGetResponsePDU(info, remoteip, remoteport);	
		
	}
	
	public static void processSetRequestPDUMessage(byte set_reqData[], String remoteip, int remoteport)
	{
		  //Get Request ID
                logger.info(DatatypeConverter.printHexBinary(set_reqData));
                int pos = 0;
                int reqid_len = set_reqData[1] & 0xFF;
                byte requestID[] = new byte[reqid_len];
                System.arraycopy(set_reqData, pos+2, requestID, 0, requestID.length);
              	BigInteger reqID = new BigInteger(requestID); 

                pos = pos + 2 +reqid_len;

                //ErrorValue
                int error_value_len = set_reqData[pos+1] & 0xFF;
                byte error_value[] = new byte[error_value_len];
                System.arraycopy(set_reqData, pos+2, error_value, 0, error_value_len);
                int value = new BigInteger(error_value).intValue(); 

                pos = pos +2+error_value_len;

                //Error Index
                int error_index_len = set_reqData[pos+1] & 0xFF;
                byte error_index[] = new byte[error_index_len];
                System.arraycopy(set_reqData, pos+2, error_index, 0, error_index_len);
                int error_index_value = new BigInteger(error_index).intValue(); 

                pos = pos +2+error_index_len;

                //Varbind list
                int list_length = set_reqData[pos+1] & 0xFF;
                byte varbind_list[] = new byte[list_length];

                pos = pos + 2;
                System.arraycopy(set_reqData, pos, varbind_list, 0, varbind_list.length);
                logger.info(DatatypeConverter.printHexBinary(varbind_list));
		
		 /*Parsing and processing the Varbind List
                  *varbind list will contains list varbind..
                  *Varbind consists of pair of OID and associated value in ASN1 notation*/	
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
			logger.info( "[SET REQUEST RECVD --][OBJECT ID]["+objectid+"]");

			index = index+2+object_id.length;

			//Get Values
			byte type = varbind_list[index];
			if(type == SNMPConstants.STRING_OCTET)
			{
				int value_len = varbind_list[index+1] & 0xFF;
				byte obj_value[] = new byte[value_len];
				System.arraycopy(varbind_list, index+2, obj_value, 0, obj_value.length);
				String Object_value = new String(obj_value);
				logger.info( "[ OBJECT VALUE -- ]["+Object_value+"]");
				index = index + obj_value.length + 2;
				
				//SET THE VALUES IN THE MIB	
				MIBManager.storeObjectIDvalue(objectid, Object_value);
			}
			else
			{
				index = index + 2;
			}
		}	
			
	}	
	public static void generateGetResponsePDU(SNMPInfo info, String remoteip, int remoteport)
	{	
		try
		{		
			byte responsePDU[] = SNMPUtils.constructGetResponsePDU(info);		
			byte SNMPMessage[] = SNMPUtils.constructSNMPMessgae(responsePDU, (byte)0);
			byte SNMPPacket[] = SNMPUtils.constructSNMPPacket(SNMPMessage);

			/*Send Get Response SNMP PDU Message 
			  to SNMP Manager with the specified OID value*/	
			InetAddress addr = InetAddress.getByName(remoteip);
			logger.info( "[DATA SENT TO ][REMOTEADDR]["+remoteip+":"+remoteport+"]");
			if(!ConfManager.isLocalHostTestingEnabled())
			{
				SNMPNetwork.writeUDPData(SNMPPacket, serverSocket, addr, remoteport);
			}
			else
			{
				SNMPNetwork.writeUDPData(SNMPPacket, serverSocket, addr, ConfManager.getManagerPort());
			}
			
			logger.info( " [ SEND GET RESPONSE ]");		 	
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}	
		
	}
	
	public static void generateTrapMessage(SNMPInfo info, String remoteip)
	{
		try	
		{
			byte responsePDU[] = SNMPUtils.getTrapMessage(info);
			byte SNMPMessage[] = SNMPUtils.constructSNMPMessgae(responsePDU, (byte)0);
			byte SNMPPacket[] = SNMPUtils.constructSNMPPacket(SNMPMessage);
			
			InetAddress addr = InetAddress.getByName(remoteip);	
			SNMPNetwork.writeUDPData(SNMPPacket, serverSocket, addr, ConfManager.getManagerPort());	
			logger.info( "[SEND TRAP MESSAGE --]");
		}
		catch(Exception e)
		{
		}	
	} 

	public static void main(String args[])
	{
		try
		{
			String work_dir = System.getProperty("user.dir");
                        System.setProperty("server.home", work_dir);

                        ConfManager.loadConfFile();

			SNMPNetwork network = new SNMPNetwork();
			
			//Intialize server and bind socket on port 162
                        serverSocket = network.initializeSocket(ConfManager.getAgentPort());
                        network.setSNMPType("agent");

			Thread thread = new Thread(network);
			thread.setName("UDPNETWORK"); //No I18N
			thread.start();
			
			MIBManager.storeOIDlexicographical("1.3.4.234.1.8.6", "true"); //MicrophoneStatus
			MIBManager.storeOIDlexicographical("1.3.4.234.1.8.7", "100MB"); //RecvQueue max size
			MIBManager.storeOIDlexicographical("1.3.4.234.1.8.8", "50F");  //Temperature
			
			HashMap oid_map = new HashMap();
			oid_map.put("1.3.4.234.1.8.8", "80F");
			SNMPInfo info = new SNMPInfo();
			info.setMIBValueMap(oid_map);
			info.setEnterpriseOID("1.3.4.234.1");
			//generateTrapMessage(info, "192.168.18.123");
			
		}	
		catch(Exception e)
		{
			e.printStackTrace();
		}	

	}
}
