package source.com.snmp;

import java.util.Properties;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.logging.*;

public class ConfManager
{
	private static Logger logger = Logger.getLogger(ConfManager.class.getName());	
	private static String serverHome = null;
	
	static
        {
                serverHome = System.getProperty("server.home");
        }
	
	private static String serverConfFile = serverHome+File.separator+"conf"+File.separator+"snmp.properties";
		
	private static Properties serverconf;
	
	private static boolean islocalhosttestingenabled = false;
	private static int agentport = 162;
	private static int managerport = 161;
	private static String agentaddr = "localhost"; 
	
	public static void loadConfFile()
	{
		serverconf = getProperties(serverConfFile);
		
		islocalhosttestingenabled = Boolean.valueOf(serverconf.getProperty("islocalhosttestingenabled",String.valueOf(islocalhosttestingenabled)));	
		
		agentport = Integer.parseInt(serverconf.getProperty("agentport",""+agentport));
		managerport = Integer.parseInt(serverconf.getProperty("managerport", ""+managerport));
		
		agentaddr = serverconf.getProperty("agentaddr" , ""+agentaddr);
		
			
	}	

	public static Properties getProperties(String propsFile)
        {
                try
                {
  			logger.info( "LOADING PROPERTIES "+propsFile); 
                        Properties props = new Properties();
                        props.load(new FileInputStream(propsFile));
                        return props;
                }
                catch(Exception e)
                {
			logger.info( "[UNABLE TO LOAD CONF FILE --]");
                        return null;
                }
        }
	
	public static boolean isLocalHostTestingEnabled()
	{	
		return islocalhosttestingenabled;
	}
	
	public static int getAgentPort()
	{
		logger.info( "[AGENT PORT -- ]["+agentport+"]");
		return agentport;
	}
	
	public static int getManagerPort()
	{
		logger.info("[ MANAGER PORT -- ]["+managerport+"]");
		return managerport;
	}
	
	public static String getAgentAddr()
	{
		return agentaddr;
	}

	
}	


