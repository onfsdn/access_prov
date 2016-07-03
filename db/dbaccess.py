import sqlite3

# Inserting data into Server table
def insertServertable(internal_ip,external_ip,authServer_ip,internal_mac, \
	external_mac, authServer_mac, internal_port,external_port,authServer_port,sdnController_ip):
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	conn.execute("INSERT INTO servertable (internal_ip,external_ip,authServer_ip, \
		internal_mac,external_mac, authServer_mac,internal_port,external_port, \
		authServer_port,sdnController_ip) VALUES (?,?,?,?,?,?,?,?,?,?)" \
	    ,(internal_ip,external_ip,authServer_ip,internal_mac,external_mac, \
	    authServer_mac,internal_port, external_port,authServer_port,sdnController_ip));

	conn.commit()
	print "Records stored successfully";
	conn.close()


# Fetches the data from Server table
def getServertable():
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	cursor = conn.execute("SELECT * FROM servertable");
	conn.commit()

	server_list=[]
	for row in cursor:
		values = list(row)
		server_list.append(values)

	print "Records fetched successfully";
	conn.close()
	return server_list


# Retrieves the server configuration data from database
def getServerconfig():
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	cursor = conn.execute("SELECT * FROM servertable");
	conn.commit()

	keys = [tuple[0] for tuple in cursor.description]

	server_list=[]
	for row in cursor:
		values = list(row)
		server_list.append(values)
		server_dict = dict(zip(keys, values))

	print "Server config sent successfully";
	conn.close()
	return server_dict


# Inserting user data when the admin creates an account
def insertBeforeLogin(name,passwd,user_group,evict_time,status):
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	conn.execute('''INSERT INTO usertable (name,pass,user_group,evict_time,status) 
		values (?,?,?,?,?)''',(name,passwd,user_group,evict_time,status));

	conn.commit()
	print "Records created successfully";
	conn.close()


# Insertion of data when user logs in
def insertAfterLogin(name,device, ip_addr, status):
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	conn.execute("UPDATE usertable set device=?, ip_addr=?, status=? WHERE name=? \
	      ",(device,ip_addr,status,name));

	conn.commit()
	print "Records created successfully";
	conn.close()


# Deleting a user account from the database
def deleteUser(name):
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	cursor = conn.execute("DELETE FROM usertable WHERE name=(?)",(name,))
	conn.commit()

	print "Records deleted successfully";
	conn.close()


# Retreiving all the user entries in the database
def getAllUsers():
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	cursor = conn.execute("SELECT * from usertable")

	keys = [tuple[0] for tuple in cursor.description]

	user_list=[]
	for row in cursor:
		values = list(row)
		user_list.append(values)

	conn.close()
	return user_list


# Getting user details from the database
def getUserDetails(name):
	conn = sqlite3.connect('db//test.db')
	print "Opened database successfully";

	cursor = conn.execute("SELECT * FROM usertable WHERE name=(?)",(name,))

	keys = [tuple[0] for tuple in cursor.description]
	user_dict={}

	for row in cursor:
		values = list(row)
		user_dict = dict(zip(keys, values))

	return user_dict


# Returns true if user is already logged in
def isOnline(name):
	user_details = getUserDetails(name)

	if not user_details:
		return False

	if user_details['status'] == 'Online':
		return True
	else:
		return False


# Checks if the username, password are valid
def isValid(name,passwd):
	conn = sqlite3.connect('db//test.db')
	cursor = conn.execute("SELECT pass from usertable where name= '%s'"% name)

	for row in cursor:
		if passwd == row[0]:
			return True
		else:
			return False
	conn.close()

