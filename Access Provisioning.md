## Solution Notes - Dynamic Access Provisioning 

-  Pramod Shanbhag
-  Abhilash R
-  Harish Reddy V
-  Madhusudhan S.

## Complex Access Control and Access Selective Process

- Selective Access Provisioning - Employees should have access to servers & internet, while the guests should have internet-only access.


- Selective Access Control - Allow only guest access for few hours


- Access control using ‘MACs’ and ‘IPs‘  - For example, allow ‘172.10.176.25’  or block ‘5e:ee:75:63:9f:ac’


- There is no centralized view of the Access Network


## Solution Approach


- Admin defines Access Policies for Users and User Groups through Admin UI


- User trying to access network is redirected to Authentication Server. The packet redirection is done using header re-write flows.


- Authentication server informs SDN Controller on successful authentication using REST APIs


- SDN Controller provisions and manages Access based on defined Access Policies by programming the flows.


 
[Dynamic Access Provisioning](https://github.com/geethabg/Images/blob/master/DynamicAccessProvisioning.png) 

  ![alt text](DynamicAccessProvisioning.png "Dynamic Access Provisioning")

 

## Deployment Details

#IP Config

vi /usr/local/etc/ryu/ryu.conf

wsapi_host=ip_addr

wsapi_port=port_no

vi ryu/app/dynamic_access.py

_ipaddr='http://ip_addr:'

_ipaddr_port=port_no



#Run
./bin/ryu-manager --app-lists ryu/app/dynamic_access_main.py ryu/app/ofctl_rest.py

#Running Authentication Server
- Clone the repo.
- Run createDB.py inside db directory. 

cd db

python db/createDB.py

cd ..

- Run app.py 

sudo python app.py

- View the admin dashboard using the http://127.0.0.1/admin_login address. You can add the user and server details.  
- Users can login to http://127.0.0.1 using a valid login credentials.


