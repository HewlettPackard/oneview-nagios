#!/usr/bin/python
# -*- coding: utf-8 -*-###
# Copyright (2018) Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

import logging
import json
import os
from time import sleep
import subprocess
import sys
import re
import requests
import base64
import signal
from datetime import datetime

from common.send_nrdp import *


##################################################################
# Caption Ctrl+C
##################################################################
def signal_handler(signal, frame):
	# print('You pressed Ctrl+C! Exiting.')
	logging.info('You pressed Ctrl+C! Exiting.')
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


##################################################################
# Function which is to be called at the beginning to check if this
# host is present in Nagios server.
##################################################################
def check_service_existence(serviceName, hostName, oneViewIP, nagiosDetails):
	recordCount = 0  # No records by default
   
	urlPrefix = 'http://'
	url = urlPrefix + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/objects/servicestatus'
	params = {
		'name': serviceName,
		'pretty': ['1', '1'],
		'apikey': nagiosDetails["apikey"]
	}

	response = requests.get(url, params=params,verify=False)
	serviceStat = response.json()
	
	if response.status_code == 200:
		recordCount = int(serviceStat["recordcount"])
	else:
		logging.error("Failed check service existence - \"{}\", Creating it".format(serviceName))

	return recordCount


##################################################################
# Function which is to be called at the beginning to check if this
# host is present in Nagios server.
##################################################################
def check_hostgroup_existence(hostGroupName, oneViewIP, nagiosDetails):
	status = 0  # Host Group not yet found

	urlPrefix = 'http://'
	url = urlPrefix + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/objects/hostgroup'
	params = {
		'apikey': nagiosDetails["apikey"],
		'pretty': '1'
	}

	response = requests.get(url, params=params, verify=False)

	hostGrpStat = response.json()
	logging.info("hostGrpStat :- " + str(hostGrpStat))

	if response.status_code == 200:
		#numRecords = int(hostGrpStat["hostgrouplist"]["recordcount"])
		
		# Getting message in this format from NagiosXI in .22 server; hostgrouplist not present for single or multiple groups
		numRecords = int(hostGrpStat["recordcount"]) 
	  
		if numRecords == 0:
			status = 0  # No hostgroups present at all. Update the status as not found

		elif numRecords == 1:
			# One hostgroup if present, the return value is not an array. We cannot iterate and hence checking the hostgroup name directly.
			if hostGroupName == (hostGrpStat["hostgroup"]["hostgroup_name"]):
				status = 1  # Update the status as found.

		else:
			# Check if the tag "hostgrouplist" is present when multiple hostgroups are present. 
			print(str(hostGrpStat))
			#for member in hostGrpStat["hostgrouplist"]["hostgroup"]:
			for member in hostGrpStat["hostgroup"]:
				if hostGroupName == member["hostgroup_name"]:
					logging.info("Host Group " + hostGroupName + " exists.")
					status = 1  # Update the status as found.
	else:
		logging.error("Error which checking hostgroup status. Command:- " + str(cmd))

	return status

	

##################################################################
# Function called to apply the new config by restarting nagios xi
# 
##################################################################
def apply_config_and_restart_nagios(nagiosDetails):
	retCode = 0 # OK at the beginning
	# Actual command :- 
	# response = requests.post('http://10.188.239.22/nagiosxi/api/v1/system/applyconfig?apikey=WhNXoMABXiR7WMNO3RMN6a34oGPp6TY2qLg8NPY0868k9U9r3be8kgrLVhahq8Da')
	
	URI = "http://" + nagiosDetails["nagiosHost"] + "/nagiosxi/api/v1/system/applyconfig?apikey=" + nagiosDetails["apikey"]
	
	# Apply config URI (used to restart Nagios XI)
	#print("ApplyConfig URI  = :- " + URI)
	response = requests.post(URI)
	retVal = int(response.status_code)
	retStat = json.loads(response.text)
	
	try:
		status = retStat["success"]
		logging.info("Restart Nagios with retVal :- " + str(retVal) + " and retStat :- " + str(retStat))
		retCode = 0
	except:
		status = retStat["error"]
		logging.info("Restart Nagios failed with retVal :- " + str(retVal) + " and retStat :- " + str(retStat) + ". Plugin exiting.")
		retCode = 1 # Something is wrong. 
		sleep(1)
		sys.exit(1) # Exit for now.
	
	return retCode
	

##################################################################
# Function called to send alert status to Nagios server
##################################################################
def notify_nagios(data, nagiosDetails, target):
	try:
		uri = 'http://' + nagiosDetails["nagiosHost"] + '/nrdp/'
		token = nagiosDetails["secretToken"]
		host = data["resource_name"]

		# If calling this API for updating status of service, include that also.
		service = ''
		if target == 'SERVICE':
			service = data["service_name"]

		status = str(data["severity"])
		message = '\'' + data["timestamp"] + " *** " + data["description"] + \
		" *** " + str(data["correctiveAction"]) + '\''

		send_nrdp(uri, token , host, service, status, message, '', '')
	except Exception as e:
		logging.error('Updating alert Failed!. alert-name: {} '.format(service))
	


##################################################################
# Create a service against the defined host
# Get service name to be created and host name for which
# service is to be created
##################################################################
def create_service(data, nagiosDetails):
	# Sample command format: for reference only.
	
	try:
		hostName = data["resource_name"]
		serviceName = data["service_name"]

		urlPrefix = 'http://'
		params = {
			'pretty': ['1', '1'],
			'apikey': nagiosDetails["apikey"]
		}
		url = urlPrefix + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/config/service'
		
		data = {
			'host_name': hostName,
			'service_description': serviceName,
			'check_command': 'check-host-alive\!3000,80%\!5000,100%',
			'check_interval': '5',
			'retry_interval': '5',
			'active_checks_enabled': '0',
			'max_check_attempts': '2',
			'check_period': '24x7',
			'contacts': 'nagiosadmin',
			'notification_interval': '5',
			'notification_period': '24x7'
		}

		response = requests.post(url, params=params, data=data)
		sleep(1)
	except:
		logging.error("Service creation failed. Check service details.")


def validate_input_config(oneViewDetails, nagiosDetails, hardwareTypes, alertTypes):
	# validate OneView details
	validate_oneview_details(oneViewDetails)
	# validate Nagios details
	validate_nagios_details(nagiosDetails)
	# validate hardware types entered
	validate_hardware_category(oneViewDetails,hardwareTypes)
	# validate alert types entered
	validate_alert_types(oneViewDetails, alertTypes)
	return 0


##################################################################
# Validate OneView appliance details.
# Function needs to be added with new parameters when updated in Json
##################################################################
def validate_oneview_details(oneViewDetails):
	
	required_fields = ('host','alias','user','passwd','action','route','process_onetime_alerts','events_dated_from','alert_type')
	# Validate inputs
	if not all(keys in oneViewDetails for keys in required_fields):
		logging.error("Oneview details incomplete.")
		logging.error(
			"Please ensure following values present in input json file:- host, user, passwd, action, route, process_onetime_alerts, events_dated_from")
		sys.exit(1)
		
	# Decode password
	password = base64.b64decode(oneViewDetails['passwd'].encode('utf-8')) 
	oneViewDetails['passwd'] = password.decode('utf-8')


##################################################################
# Validate Nagios server details.
# Function needs to be added with new parameters when updated in Json
##################################################################
def validate_nagios_details(nagiosDetails):
	required_fields = ('nagiosHost','secretToken','apikey')
	if not all(keys in nagiosDetails for keys in required_fields):
		logging.error("Nagios server details incomplete.")
		logging.error("Please ensure following values present in input json file:- nagiosHost, secretToken, apikey")
		sys.exit(1)


##################################################################
# Validate hardware types give in input file
# Function needs to be added with new parameters when updated in Json
##################################################################
def validate_hardware_category(oneViewDetails,hardwareTypes):

	# Get hardware category as list
	hardwareType = oneViewDetails["alert_hardware_category"]
	alertHardwareTypes = hardwareType.split(':')
	# config['alertHardwareTypes'] = alertHardwareType

	for hardware in alertHardwareTypes:		
		if not hardware in hardwareTypes:
			logging.error("Hardware type - \"{}\" is not permissible. Valid types - {} \nExiting.. ".format(hardware,hardwareTypes))
			print("Hardware type - \"{}\" is not permissible. Valid types - {} \nExiting.. ".format(hardware,hardwareTypes))
			sys.exit(1)
		elif not hardware:
			logging.error("Enter interested hardware types in config file. Exiting...")
			sys.exit(1)

##################################################################
# Validate Validate alert types give in input file
# Function needs to be added with new parameters when updated in Json
##################################################################
def validate_alert_types(oneViewDetails, alertTypes):
	## Validating the alert type to be sent to Nagios
	#
	inputAlertTypes = oneViewDetails["alert_type"].split(':')
	inputAlertTypes = [x.lower() for x in inputAlertTypes] # User interested alert types
	# config['inputAlertTypes'] = inputAlertTypes

	alertTypes = [a.lower() for a in alertTypes] # List of permissible alerts
	
	## All of the alert types entered by user should match with actual alert types.
	## If there is any mismatch, the same is printed in the log file and program will exit. 
	for alertType in inputAlertTypes:		
		if not alertType in alertTypes:
			logging.error("Alert type mismatch : " + alertType + ". Kindly review and restart the plugin.")
			sys.exit(1)
		elif not alertType:
			logging.error("Enter interested alert types in config file. Exiting...")
			sys.exit(1)

##################################################################
# Function which is to be called to process the Json object
# and extract hardware details.
##################################################################
def scan_server_hardware(serverHardware):
	serverList = []
	try:
		hwMembers = serverHardware["members"]
	except Exception as e:
		logging.error("Error in getting list of server hardware. " )
		logging.error(e)
		return (-1)

	if hwMembers:
		# Loop through the Json objects of individual hardware and create an array of server hardware.
		for member in hwMembers:
			serverDict = {}
			serverDict["name"] = trim_name(member["name"])
			serverDict["status"] = member["status"]
			serverList.append(serverDict)

		logging.info("The hardware detected are as follows:- " + str(serverList))

	else:
		logging.info("No hardware present in this category.")

	return serverList


##################################################################
# Function to be called for removing comma and replacing
# multiple spaces with underscores.
##################################################################
def trim_name(entityName):
	# Replacing ' ' and ',' with '_'with REGEX
	entityName = re.sub('[^A-Za-z0-9.]+', '_', entityName)

	return entityName

##################################################################
# Function to be called get all service list from nagios
# 
##################################################################
def get_all_services(nagiosDetails):

	params = (
		('apikey', nagiosDetails["apikey"]),
		('pretty', '1'),
	)
	URI = 'http://' + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/objects/servicestatus'

	response = requests.get(URI, params=params)

	# Form services list
	hostServiceDict = {}

	if response.status_code == 200:
		response = response.json()
		# If only one service exists
		if int(response['recordcount']) == 1:
			host = response['recordcount']["host_name"]
			service = response['recordcount']["name"]
			hostServiceDict[host] = [service]

		# If more than one service exists
		elif int(response['recordcount']) > 1:
			serviceList = response["servicestatus"]
			# Form dict with hostname as key and [] as value and append later
			hosts = get_all_hosts(nagiosDetails)
			for host in hosts:
					hostServiceDict[host] = []
			# Append service names to list
			for service in serviceList:
					hostServiceDict[service["host_name"]].append(service['name'])
	else:
		logging.error("Failed to get all services, Exiting... msg - {}".format(response.text))
		sys.exit(response.text)
	# print(hostServiceDict)
	return hostServiceDict

##################################################################
# Function to be called get all hosts list from nagios
# 
##################################################################
def get_all_hosts(nagiosDetails):

	params = (
		('apikey', nagiosDetails["apikey"]),
		('pretty', '1'),
	)
	URI = 'http://' + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/objects/hoststatus'

	response = requests.get(URI, params=params)

	# Form hosts name list
	hostsList = []
	if response.status_code == 200:
		response = response.json()
		# If only one host present
		if int(response['recordcount']) == 1:
			# append host  name to list
			hostsList.append(response["hoststatus"]['name'])
		# If more than one hosts
		elif int(response['recordcount']) > 1:
			respList = response["hoststatus"]

			for host in respList:
				# Append host name to list
				hostsList.append(host["name"])
	else:
		logging.error("Failed to get all hosts, Exiting... msg - {}".format(response.text))
		sys.exit(response.text)

	return hostsList


##################################################################
# Init the logging module.
##################################################################
def initialize_logging(oneViewIP, loggingLevel='WARNING'):
	# Initialize the log file path, log format and log level
	logfiledir = os.getcwd() + os.sep + "logs"
	if not os.path.isdir(logfiledir):
		os.makedirs(logfiledir)

	logfile = logfiledir + os.sep +"OneViewNagios_{}.log".format(oneViewIP)
	if os.path.exists(logfile):
		fStats = os.stat(logfile) 
		if fStats.st_size >= 1024000:
			#Backing up logfile if size is more than 1MB
			timestamp = '{:%Y-%m-%d_%H_%M}'.format(datetime.now())
			#Backup logfile
			os.rename(logfile,logfiledir + os.sep + 'OneViewNagios_{}_'.format(oneViewIP)+ timestamp +".log")
			#Create empty logfile
			open(logfile, 'a').close()
	else:
		#Create empty logfile
		open(logfile, 'a').close()

	# Init the logging module with default log level to INFO. 
	logging.basicConfig(filename=logfile, format='%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%d-%m-%Y:%H:%M:%S', level=loggingLevel)




