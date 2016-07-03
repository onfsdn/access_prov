from flask import Flask, render_template, redirect, url_for, request
import requests
from pprint import pprint
import sqlite3
from db import dbaccess,timer
import json


# create the application object
app = Flask(__name__)

# Global variable
success_string=""

# Redirects to user login page
@app.route('/')
def home():
    return redirect(url_for('userLogin'))  

# User adding page
@app.route('/user_add',methods=['GET', 'POST'])
def userAdd():
    error =None

    if request.method == 'GET':
        items = dbaccess.getAllUsers()
        return render_template('user_add.html',items=items)

    if request.method == 'POST':
        username = str(request.form['username'])
        passwd = str(request.form['password'])
        user_group = str(request.form['user_group'])
        evict_time = str(request.form['evict_time'])
        if not evict_time:
            evict_time_int = 0
        else:
            evict_time_int = int(evict_time)
        status = "Offline"

        dbaccess.insertBeforeLogin(username,passwd,user_group,evict_time_int,status)
        items = dbaccess.getAllUsers()

        return render_template('user_add.html',items=items)
    
    return render_template('user_add.html',error=error)


# Adding new server details
@app.route('/server_add', methods=['GET','POST'])
def serverAdd():
    error =None

    if request.method == 'GET':
        items = dbaccess.getServertable()
        return render_template('server_add.html',items=items)

    if request.method == 'POST':
        internal_ip = str(request.form['internal'])
        external_ip = str(request.form['external'])
        authServer_ip = str(request.form['authentication'])
        internal_mac = str(request.form['internal_mac'])
        external_mac = str(request.form['external_mac'])
        authServer_mac = str(request.form['authentication_mac'])
        internal_port = str(request.form['internal_port'])
        external_port = str(request.form['external_port'])
        authServer_port = str(request.form['authentication_port'])
        sdnController_ip = str(request.form['sdnController'])
        dbaccess.insertServertable(internal_ip,external_ip,authServer_ip,internal_mac,external_mac, \
            authServer_mac,internal_port,external_port,authServer_port,sdnController_ip)
        items = dbaccess.getServertable()


        server_config = dbaccess.getServerconfig()
        del(server_config['sdnController_ip'])

        url = 'http://127.0.0.1:5010/server_config'

        sendConfig(server_config,url)

        return render_template('server_add.html',items=items)

    return render_template('server_add.html')


# Returns login success page
@app.route('/login_success', methods=['GET','POST'])
def loginSuccess():
    return render_template('login_success.html', success_string=success_string)


# Admin login page
@app.route('/admin_login',methods=['GET','POST'])
def admin():
    error =None

    sample_dict = (vars(request))
    sam_dict = sample_dict['environ']

    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials'
        else:
            return redirect(url_for('userAdd'))
    
    return render_template('admin_login.html',error=error)

#Deleting the user
@app.route('/user_delete',methods=['GET','POST'])
def userDelete():
    error =None
    sample_dict = (vars(request))

    if request.method == 'GET':
        items = dbaccess.getAllUsers()
        return render_template('user_delete.html',items=items)

    if request.method == 'POST':
        username = str(request.form['username'])
        user_dict = dbaccess.getUserDetails(username)
        dbaccess.deleteUser(username)
        success = "User successfully deleted !!"
        data = {'user_name':user_dict['name'], 'ip_address':user_dict['ip_addr'],'policy_type':user_dict['user_group']}
        url = 'http://127.0.0.1:5010/evict_user'
        sendConfig(data,url)

        items = dbaccess.getAllUsers()

        return render_template('user_delete.html',items=items)

   
    return render_template('user_delete.html',error=error)

# User Login page
@app.route('/user_login',methods=['GET','POST'])
def userLogin():
    error =None
    global success_string

    request_dict = (vars(request))
    environ_dict = request_dict['environ']
    ip_addr = str(environ_dict['REMOTE_ADDR'])

    if request.method == 'POST':
        if dbaccess.isOnline(str(request.form['username'])):
            error = 'You are already logged in'
        elif not dbaccess.isValid(str(request.form['username']), str(request.form['password'])):
            error = 'Invalid Credentials'
        else:
            username = str(request.form['username'])

            # Device types being detected when the user logs in
            device = getDeviceType(environ_dict)
            ip_addr = str(environ_dict['REMOTE_ADDR'])
            status = "Online"

            dbaccess.insertAfterLogin(username,device,ip_addr,status)
            user_dict = dbaccess.getUserDetails(username)
            if user_dict['user_group'] != 'Employee':
                # Link timer here
                timer.startTimer(username,user_dict['evict_time'])
            
            data = {'user_name':user_dict['name'], 'ip_address':user_dict['ip_addr'],'policy_type':user_dict['user_group']}

            url = 'http://127.0.0.1:5010/authenticated_user'
            sendConfig(data,url)
            success_string = 'Your login is successful from your ' + device + " device with IP " + ip_addr + "."

            return redirect(url_for('loginSuccess'))
    return render_template('user_login.html',error=error)


# Sends configuration data to the controller
def sendConfig(data,url):
    data_json = json.dumps(data)
    print 'JSON being sent - ', data_json
    headers = {'Content-type': 'application/json'}
    # response = requests.post(url, data=data_json, headers=headers)
    # pprint.pprint(response.json())

def getDeviceType(environ_dict):
    if 'Ubuntu' in environ_dict['HTTP_USER_AGENT']:
        device = "Ubuntu"
    if 'Macintosh' in environ_dict['HTTP_USER_AGENT']:
        device = "Macintosh"
    if 'iPad' in environ_dict['HTTP_USER_AGENT']:
        device = "iPad"
    if 'iPhone' in environ_dict['HTTP_USER_AGENT']:
        device = "iPhone"
    if 'iPod' in environ_dict['HTTP_USER_AGENT']:
        device = "iPod"
    if 'Android' in environ_dict['HTTP_USER_AGENT']:
        device = "Android"
    if 'Windows' in environ_dict['HTTP_USER_AGENT']:
        device = "Windows"

    return device

# start the server with the 'run()' method
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=80)
