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

'''
This script deletes all hosts and services except the localhost and services related localhost.

'''

import json
import requests
from time import sleep

def apply_config_and_restart_nagios(nagiosDetails):
	retCode = 0 
	# Actual command :- 
	# response = requests.post('http://10.188.239.22/nagiosxi/api/v1/system/applyconfig?apikey=WhNXoMABXiR7WMNO3RMN6a34oGPp6TY2qLg8NPY0868k9U9r3be8kgrLVhahq8Da')
	
	URI = "http://" + nagiosDetails["nagiosHost"] + "/nagiosxi/api/v1/system/applyconfig?apikey=" + nagiosDetails["apikey"]
	
	# Apply config URI (used to restart Nagios XI)
	print("Restarting nagios after deleting config")
	
	response = requests.post(URI)
	retVal = int(response.status_code)
	retStat = json.loads(response.text)
	#print(retStat)
	
	try:
		status = retStat["success"]
		print("Restart Nagios with retVal :- " + str(retVal) + " and retStat :- " + str(retStat))
		retCode = 0
	except:
		status = retStat["error"]
		print("Restart Nagios with retVal :- " + str(retVal) + " and retStat :- " + str(retStat) + ". Plugin exiting.")
		retCode = 1 # Something is wrong. 
		sleep(1)
		sys.exit(1) # Exit for now. 
	
	return retCode
	

def delete_all_services_except_localhost_services(nagiosDetails):
	
	# Get a list of all services to delete them one by one - Do not delete services of localhost
	params = (
		('apikey', nagiosDetails["apikey"]),
		('pretty', '1'),
	)
		
	URI = 'http://' + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/objects/servicestatus'
	print("Get service list URI = ", URI)

	response = requests.get(URI, params=params)
	response = json.loads(response.content)
	
	print("Num services - " + str(response["recordcount"]) )

	serviceList = response["servicestatus"]

	for service in serviceList:
				
		# Do not delete services of localhost
		if service["host_name"] == 'localhost':
			continue
				
		params = (
			('apikey', nagiosDetails["apikey"]),
			('pretty', '1'),
			('host_name', service["host_name"]),
			('service_description', service["name"]),
		)
		
		URI = 'http://' + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/config/service'
		print("Delete service URI = ", URI, "Deleting service - ", service["name"])
		#sleep(5)
		response = requests.delete(URI, params=params)
		sleep(0.1)
		
	return 0
	
def delete_all_hosts_except_localhost(nagiosDetails):
			
	# Get a list of all hosts to delete them one by one - Do not delete localhost
	params = (
		('apikey', nagiosDetails["apikey"]),
		('pretty', '1'),
	)
	
	URI = 'http://' + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/objects/hoststatus'
	print("Get host list URI = ", URI)

	response = requests.get(URI, params=params)
	response = json.loads(response.content)
	
	print("Num hosts - " + str(response["recordcount"]) )

	hostList = response["hoststatus"]
	
	# JSON format differs if it is a single entry. 
	if int(response["recordcount"]) == 1:
		print("Not deleting localhost")
		return 0
	
	else:
		for host in hostList:
			# Do not delete localhost
			print("Hostname = ", host["name"])
			if host["name"] == 'localhost':
				continue

			params = (
				('apikey', nagiosDetails["apikey"]),
				('pretty', '1'),
				('host_name', host["name"])
			)
			URI = 'http://' + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/config/host'
			response = requests.delete(URI, params=params)

			print("Delete host URI = ", URI, "Deleting host - ", host["name"])
			#sleep(5)
			response = requests.delete(URI, params=params)
			sleep(0.1)
		
	return 0


if __name__ == '__main__':
	import sys
	import argparse
	from datetime import datetime, timedelta
	
	parser = argparse.ArgumentParser(add_help=True, description='Usage')
	parser.add_argument('-i','--input_file',dest='input_file', required=True,
						help='Json file containing oneview and nagios details used for testing main module')
						
	# Check and parse the input arguments into python's format
	input = parser.parse_args()
						
	with open(input.input_file) as data_file:	
		inputConfig = json.load(data_file)
		
	nagiosDetails = inputConfig["nagios_config"]

	delete_all_services_except_localhost_services(nagiosDetails)	
	apply_config_and_restart_nagios(nagiosDetails)
	sleep(5)
	
	delete_all_hosts_except_localhost(nagiosDetails)
	apply_config_and_restart_nagios(nagiosDetails)
	
	
	
