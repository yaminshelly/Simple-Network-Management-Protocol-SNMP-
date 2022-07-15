List of the students : 
Shelly Revivo 315661884
Tomer Revivo 204470892
Shimon yaish 203499025
Hai Palatzi 307883363

how many hours were spent on each part : 
Manager - 25 
Agent - 25 
conf file + confManager -  12
MIBmanager -13
snmpNetwork - 10
snmpUtils - 10

How to run the code:
First it is necessary to change the "conf" configuration file manually in order to insert the appropriate ports.
If you work on 2 computers:
agent:
agentport = 161
managerport = 161
islocalhosttestingenabled = false
agentaddr = 10.0.201.14
  manager:
agentport = 161
managerport = 161
islocalhosttestingenabled = false
agentaddr = localhost


If you work on one computer -
agentport = 162
managerport = 161
islocalhosttestingenabled = true
agentaddr = localhost


now you can run the jar file (...\snmpLastVersion\out\artifacts\snmpLastVersion_jar)  of the agent by command line on cmd : 
java -jar snmpLastVersion.jar 


after you need to run the manager(...\snmpLastVersion\out\artifacts\snmpLastVersion_jar2)  by : 
java -jar snmpLastVersion.jar 


now you have 4 options on the mangerSNMP , you need to follow the instruction . 

you have user guide too . 






