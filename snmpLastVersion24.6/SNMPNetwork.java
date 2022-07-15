package source.com.snmp;

import java.net.*;
import java.io.IOException;
import java.nio.channels.*;
import java.util.logging.*;

public class SNMPNetwork implements Runnable
{
	private static Logger logger = Logger.getLogger(SNMPNetwork.class.getName());
	private DatagramSocket dgramSocket;
	private String SNMPtype;
	public void run()
        {
		try
		{
			readData();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
        }
        public void readData() throws IOException, CancelledKeyException
        {
                while(true)
                {
                        try
                        {     	
                                byte[] recvdata = new byte[2000];
                                DatagramPacket dgramPacket = new DatagramPacket(recvdata, 2000);
                                dgramSocket.receive(dgramPacket);
                                
                                byte finalpkt[] = new byte[dgramPacket.getLength()];
                                System.arraycopy(recvdata, 0, finalpkt, 0, finalpkt.length);
                      		
				SocketAddress addr = dgramPacket.getSocketAddress();	
				InetSocketAddress address = (InetSocketAddress)addr;
                		String remoteip = address.getAddress().getHostAddress();           
				
				if(SNMPtype.equals(SNMPConstants.MANAGER))
				{
					SNMPManager.handleData(finalpkt);
				}
				else if(SNMPtype.equals(SNMPConstants.AGENT))
				{	
					SNMPAgent.handleData(finalpkt, remoteip, address.getPort());
				} 
                        }
                        catch(Exception e)
                        {
				e.printStackTrace();
                        }
                }
        }
        
	public DatagramSocket initializeSocket(int port)
	{
		try
		{
			dgramSocket = new DatagramSocket(null);
			dgramSocket.setReuseAddress(true);
			dgramSocket.bind(new InetSocketAddress(port));
			logger.info( "[SOCKET INTIALIZED --- ][SERVER PORT]["+port+"]");
			return dgramSocket;
		}
		catch(BindException e)
		{
			e.printStackTrace();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}      
	
	public void setSNMPType(String type)
	{
		this.SNMPtype = type;
	}
	
	public static void writeUDPData(byte[] data, DatagramSocket socket, InetAddress address, int port)
	{
		try
		{
			DatagramPacket pkt = new DatagramPacket(data, data.length, address, port);
			socket.send(pkt);	
		}
		catch(IOException ex)
		{
		}
	}


}
