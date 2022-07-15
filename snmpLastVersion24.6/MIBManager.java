package source.com.snmp;

import java.util.*;


/* The Management Information Base, or MIB, 
 * is the database of information maintained by the agent that the manager can query or set
*/
public class MIBManager
{
	public static HashMap mib_ObjectIDValueMap = new HashMap();
	
	public static ArrayList lexigrophicalOrderOIDs = new ArrayList(); 

	/*Object ID value Map
	 * It maintains the ObjectID and corresponding values */	
	public static void storeObjectIDvalue(String objectid, Object value)
	{
		 mib_ObjectIDValueMap.put(objectid, value);
	}
	
	public static Object getObjectIDValue(String objectid)
	{
		return mib_ObjectIDValueMap.get(objectid);
	}
	
	/*There is an implied ordering in the MIB based on the order of the object identifiers. 
	*All the entries in MIB tables are lexicographically ordered by their object identifiers
	*Here we manually storing the values in lexicographical order to serve getNext Request*/	
	public static void storeOIDlexicographical(String objectid, Object value)
	{
		lexigrophicalOrderOIDs.add(objectid);
		storeObjectIDvalue(objectid, value);	
	}
	
	/*Retrieve lexicographically greater OID
		than the given OID */
	public static Object getLexigrophicalNextNode(String objectid)
	{
		for(int i=0; i<lexigrophicalOrderOIDs.size(); i++)
		{
			String OID = (String)lexigrophicalOrderOIDs.get(i);
			if(objectid.equals(OID) && (i != lexigrophicalOrderOIDs.size()-1))
			{
				return lexigrophicalOrderOIDs.get(i+1);	
			}
		}
		return null;
		
	} 
}

