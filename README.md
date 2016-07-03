## Solution Notes
Project: Dynamic Access Provisioning
Team :
 Pramod Shanbhag
 Abhilash R
 Harish Reddy V.
 Madhusudhan S.

## Problem Statement 

- Selective Access Provisioning is complex
   ‘Employees’ should have access to servers & internet, while the ‘Guests’ have internet-only access
- Selective Access Control is complex
   Allowing ‘Guest’ access only for few hours
- Access control using ‘macs’ and ‘IPs‘ complex
   Allow ‘172.10.176.25’  or block ‘5e:ee:75:63:9f:ac’
- No centralized view of the Access Network


## Solution Approach
Admin defines Access Policies for user/user group
Admin UI
User trying to access network, is redirected to Authentication Server
Packet redirection using header re-write flows.
Authentication Server informs SDN Controller on successful authentication.
REST APIs
SDN Controller provisions and manages Access based on defined Policies.
Flow program 


## Deployment
#IP Config

vi /usr/local/etc/ryu/ryu.conf

wsapi_host=ip_addr

wsapi_port=port_no

vi ryu/app/dynamic_access.py

_ipaddr='http://ip_addr:'

_ipaddr_port=port_no



#Run
./bin/ryu-manager --app-lists ryu/app/dynamic_access_main.py ryu/app/ofctl_rest.py
