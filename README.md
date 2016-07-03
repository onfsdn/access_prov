# access_prov
Dynamic Access Provisioning

# How To

#IP Config

vi /usr/local/etc/ryu/ryu.conf

wsapi_host=ip_addr

wsapi_port=port_no

vi ryu/app/dynamic_access.py

_ipaddr='http://ip_addr:'

_ipaddr_port=port_no



#Run
./bin/ryu-manager --app-lists ryu/app/dynamic_access_main.py ryu/app/ofctl_rest.py
