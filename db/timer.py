import threading
from time import sleep
import dbaccess
import json
import requests
# from db import dbaccess

class TimerThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)
 
    def run(self):
        self._target(*self._args)


# Evicts user after specified amount of time
def evictUser(username, evict_time):
	print "User logged in : username -", str(username)
	
	sleep(evict_time)
	
	user_dict = dbaccess.getUserDetails(username)
	data = {'user_name':user_dict['name'], 'ip_address':user_dict['ip_addr']}
	dbaccess.deleteUser(username)

	data = {'user_name':user_dict['name'], 'ip_address':user_dict['ip_addr'],'policy_type':user_dict['user_group']}
	server_config = dbaccess.getServerconfig()
	sdnController = server_config['sdnController_ip']
	url = 'http://'+sdnController+'5010/evict_user'
	
	print "\n!! User Eviction policy being triggered !!"
	print "-- USER : "+str(username)
	print "-- Elapsed "+str(evict_time)+" seconds. --"
	print "-- User "+str(username)+" being deleted. --"

	sendConfig(data,url)

	print "!! USER DELETED : username -" + str(username) + " !!\n"

 
# Sends configuration data to controller
def sendConfig(data,url):
    data_json = json.dumps(data)
    print 'JSON being sent - ', data_json
    print 'URL - ', url
    headers = {'Content-type': 'application/json'}
    # response = requests.post(url, data=data_json, headers=headers)
    # pprint.pprint(response.json())

# Starts the timer for user and calls timer thread
def startTimer(username,evict_time):
	print "Timer started for user - ", username
	Timer = TimerThread(evictUser, username, evict_time)
	Timer.start()
