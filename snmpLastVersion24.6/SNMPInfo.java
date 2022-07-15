package source.com.snmp;

import java.util.*;

public class SNMPInfo
{
	private int version;
	private long reqid;
	private String oid;
	private String enterprise_oid;
	private String value;
	private HashMap mibOID_valueMap = new HashMap();
	private int error_value;
	private int error_index;

	public SNMPInfo(){

	}
	
	public void setVersion(int version)
	{
		this.version = version;
	}
	
	public void setReqID(long reqid)
	{
		this.reqid = reqid;
	}
	
	public void setOID( String oid)
	{
		this.oid = oid;
	}
	
	public void setValue(String value)
	{
		this.value = value;
	}
	
	public void setEnterpriseOID(String e_oid)
	{
		this.enterprise_oid = e_oid;
	}
	
	public void setMIBValueMap(HashMap oid_valuemap)
	{
		this.mibOID_valueMap = oid_valuemap;
	}
	
	public void setErrorValue(int value)
	{
		this.error_value = value;
	}
	
	public void setErrorIndex(int value)
	{
		this.error_index = value;
	}
	
	public int getVersion()
	{
		return version;
	}
	
	public long getReqid()
	{
		return reqid;
	}
	
	public String getOID()
	{
		return oid;
	}
	
	public String getEnterPriseOID()
	{
		return enterprise_oid;
	}
	
	public String getValue()
	{
		return value;
	}
	
	public HashMap getMIBValueMap()
	{
		return mibOID_valueMap;
	}
	
	public int getErrorValue()
	{
		return error_value;
	}
	
	public int getErrorIndex()
	{
		return error_index;
	}
	
	
}
			
