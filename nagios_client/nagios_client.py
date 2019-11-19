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
import sys
import requests
import time

from time import sleep
from datetime import datetime

from common.parsing_apis import *
# from common.send_nrdp import *
from common.utils import *

# List of functions to be exported when including in other modules.
# __all__ = ['create_infra_in_nagios']

# Setting logging level of "requests" module
# This is to avoid info and debug messages of requests module being printing b/w application log messages. 
#
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("resource").setLevel(logging.WARNING)

##################################################################
# Function to update the status of host to nagios server
#
##################################################################
def update_host_status(hostName, nagiosDetails, status,description='Updating status to Nagios.',corrAction='None'):

	# Empty JSON to hold all relevant information
	data = {}
	status = status.upper()
	data["timestamp"] = str(datetime.now())
	data["resource_name"] = hostName
	data["correctiveAction"] = corrAction
	
	if status in nodeStatusMap:
		data["description"] = description

		# Get required host name to be done.
		data["severity"] = map_node_status(status)
		# logging.info("Host severity:-" + str(data["severity"]))
	else:
		logging.error("Check host status :- " + hostName + ". Its not OK.")
		data["description"] = 'Node not in valid status. Check. '

		# Node unreachable
		data["severity"] = 2 
		
	notify_nagios(data, nagiosDetails, 'HOST')



##################################################################
# Function which is to be called at the beginning to create hosts
# in Nagios server.
##################################################################
def create_host(hostName, oneViewIP, nagiosDetails):

	#status = int(check_host_existence(hostName, oneViewIP, nagiosDetails))
	#if status < 1:
	# Host not present. create it.		
	urlPrefix = 'http://'
	url = urlPrefix + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/config/host'

	params = {
		'apikey': nagiosDetails["apikey"],
		'pretty': '1'
	}

	data = {
		'host_name':str(hostName),
		'address':str(oneViewIP),
		'check_command':'check-host-alive\!3000,80%\!5000,100%',
		'active_checks_enabled':'0',
		'max_check_attempts':'2',
		'check_period':'24x7',
		'contacts':'nagiosadmin',
		'notification_interval':'5',
		'notification_period':'24x7'
	}
	try:	
		requests.post(url, params=params, data=data)
	except Exception as e:
		logging.error("Failed to create host!")
		logging.error(e)

##################################################################
# Function to add the scanned hardware to nagios. The function is
# called for server-hardware, interconnects and enclosures.
##################################################################
def update_peripherals_in_nagios(peripherals, oneViewIP, nagiosDetails):
	hostGroup = ""
	ret = 0
	hostCreationFlag = 0 # No host created yet.

	# Create all hosts. Restart and then update their status. 
	for entity in peripherals:
		# logging.info("Peripheral name to update :- ", entity["name"])
		# Create a host entry in Nagios
		# status = check_host_existence(entity["name"], nagiosDetails)
		hosts = get_all_hosts(nagiosDetails)
		if entity['name'] not in hosts:
		# if status == 0:
			create_host(entity["name"], oneViewIP, nagiosDetails)
			hostCreationFlag = 1
		
		hostGroup += entity["name"] + ","

	if hostCreationFlag == 1:
		# Apply config and restarting nagios server before updating their status'. You may have atlease 1 host created. 
		apply_config_and_restart_nagios(nagiosDetails)
		sleep(2)
	
	for entity in peripherals:
		# Update status of all hosts created
		update_host_status(entity["name"], nagiosDetails, entity["status"])  # All good in the beginning. So status = 0;

	return ret, hostGroup

##################################################################
# Function to get the peripherals details using the URI passed.
# Recursively iterate through the URI.
##################################################################
def get_hardware_info(baseURI, oneview_client, oneViewIP, nagiosDetails):

	start = 0
	totalReceived = 0
	count = 5 # Getting 5 peripherals at a time when more are present - Pagination
	total = 0
	masterHostGroup = ""
   
	while 1:
		#URI = '/rest/interconnects/?start=' + str(start) + '&count=' + str(count)
		URI = baseURI + '?start=' + str(start) + '&count=' + str(count)
		
		peripheralInfo = oneview_client.connection.get(URI)
		count = peripheralInfo["count"]
		total = peripheralInfo["total"]

		logging.info("Scanning for Peripherals")
		#print("Peripheral Info :- " + str(peripheralInfo))
		peripherals = scan_server_hardware(peripheralInfo)
		if peripherals == -1:
			logging.error("Error in detecting Peripherals.")
			break

		ret, peripheralsGroup = update_peripherals_in_nagios(peripherals, oneViewIP, nagiosDetails)
		if ret != 0:
			logging.error("Failed to add scanned peripherals to Nagios.")
			logging.error("URI - " + URI)
			logging.error("peripherals group:- " + peripheralsGroup)
			sys.exit()
		
		masterHostGroup += peripheralsGroup
		
		start += count
		totalReceived += count
		if totalReceived >= total:
			break

	sleep(1) # TODO: Check and optimize this sleep.
	return masterHostGroup

	
##################################################################
# Function to get the power stats and update to nagios
# 
##################################################################
def process_power_stats(enclName, URI, oneview_client, nagiosDetails):
	data = {}
	data["service_name"] = enclName + "_PowerSupply_Stats"
	data["resource_name"] = enclName
	
	enclPowerStats = oneview_client.enclosures.get_utilization(URI, fields='AveragePower')
	# Filling details about this power supply
	try:
		enclPowerStats = oneview_client.enclosures.get_utilization(URI, fields='AveragePower')
		#print("AvgPower used by ", enclName ," :-", enclPowerStats["metricList"][0]["metricSamples"][0][1])
		data["description"] = "Average power = " + str(enclPowerStats["metricList"][0]["metricSamples"][0][1]) + " watts."
		data["severity"] = map_service_Status( "OK" ) # KVR check the actual power stats
		data["correctiveAction"] = ". None. "
		powerTimeStamp = int(enclPowerStats["metricList"][0]["metricSamples"][0][0]) / 1000 # TS is in millisec
		data["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(powerTimeStamp))
	except Exception as e:
		logging.error("Failed to get power stats for enclosure - ", enclName)
		logging.error(e)
		data["description"] = "Failed to get power stats."
		data["severity"] = map_service_Status( "UNKNOWN" ) # KVR check the actual power stats
		data["correctiveAction"] = ". Check power status. "
		data["timestamp"] = enclPowerStats["sliceEndTime"]		
	
	notify_nagios(data, nagiosDetails, 'SERVICE')
	
##################################################################
# Function to get the power and fan bay details  using the URI passed.
# Recursively iterate through the URI and then update to Nagios.
##################################################################
def update_enclosure_peripheral_info(baseURI, oneview_client, nagiosDetails):

	start = 0
	totalReceived = 0
	count = 5
	total = 0
	ret = 0 # All OK at the beginning
	retCode = 0 # Return value for intermediate functions. All OK before calling. 
	restartFlag = 0 # To restart nagios or not
	
	# Get all services from nagios
	allServices = get_all_services(nagiosDetails)
   
	while 1:
		#URI = '/rest/interconnects/?start=' + str(start) + '&count=' + str(count)
		URI = baseURI + '?start=' + str(start) + '&count=' + str(count)
		
		peripheralInfo = oneview_client.connection.get(URI)
		count = peripheralInfo["count"]
		total = peripheralInfo["total"]
		
		for enclosure in peripheralInfo["members"]:
			enclName = trim_name(enclosure["name"])
			# Check powersupply bays service existence, if not present create it

			# Get all services for the particular enclosure
			try:
				enclosureServices = allServices[enclName]
			except KeyError:
				# If no services exist for the enclosure assign it to []
				enclosureServices = []

			powerSupplyBays = enclosure["powerSupplyBays"]
			for powerSupplyBay in powerSupplyBays:
				enclosureBayPowSupplyName = enclName + "_PowerSupplyBay_" + str(powerSupplyBay["bayNumber"])
				data = {}
				if not enclosureBayPowSupplyName in enclosureServices:
					# Power Supply bay entry does not exist. Create it first and then update its status
					logging.info("Power Supply bay entry does not exist. Create it first and then update its status via NRDP :- " + str(enclosureBayPowSupplyName))
					data["service_name"] = enclosureBayPowSupplyName
					data["resource_name"] = enclName
					create_service(data, nagiosDetails)
					restartFlag = 1
					
			# Check fanBays service existence, if not present create it
			fanBays = enclosure["fanBays"]
			for fan in fanBays:
				eachFanName = enclName + "_FanBay_" + str(fan["bayNumber"])
				# Check for the service existence.
				if not eachFanName in enclosureServices:
					# Power Supply bay entry does not exist. Create it first and then update its status
					logging.info("fan bay entry does not exist. Create it first and then update its status via NRDP :- " + eachFanName)
					data["service_name"] = eachFanName
					data["resource_name"] = enclName
					create_service(data, nagiosDetails)
					restartFlag = 1
			
			## Check for Power supply stats
			#
			serviceName = enclName + "_PowerSupply_Stats"
			if not serviceName in enclosureServices:
				# Power Supply bay entry does not exist. Create it first and then update its status
				data = {}
				data["service_name"] = serviceName
				data["resource_name"] = enclName
				logging.info("Power stats entry does not exist. Create it first and then update its status via NRDP :- " + data["service_name"])
				create_service(data, nagiosDetails)
				restartFlag = 1

			# Create all the entries and restart at end. Then update all the entries with descriptions. 
			# No need to restart Nagios for every service creation. 
			#
			if restartFlag == 1:		
				retCode = apply_config_and_restart_nagios(nagiosDetails)
				if retCode != 0:
					logging.error("Error in applying config and restarting Nagios. Exiting python plugin. ")
					sys.exit(1)
				sleep(2)
				restartFlag = 0 # Reset the flag
			
			## Each power supply details of all the bays in this enclosure 
			# Update powerSupplyBay services
			for powerSupplyBay in powerSupplyBays:
				data = {}
				enclosureBayPowSupplyName = enclName + "_PowerSupplyBay_" + str(powerSupplyBay["bayNumber"])				

				# Filling details about this power supply to update the status
				data["resource_name"] = enclName
				data["service_name"] = enclosureBayPowSupplyName
				data["severity"] = map_service_Status( powerSupplyBay["status"] )
				data["timestamp"] = str(datetime.now())
				data["description"] = powerSupplyBay["devicePresence"] + " *** " + powerSupplyBay["model"] + " *** " + powerSupplyBay["powerSupplyBayType"]
				data["correctiveAction"] = ". NA. "
				notify_nagios(data, nagiosDetails, 'SERVICE')
				sleep(1)
				
			## Adding Fan details for this enclosure
			## Each fan details of all the bays in this enclosure
			# Update fan bays services 
			for fan in fanBays:
				eachFanName = enclName + "_FanBay_" + str(fan["bayNumber"])
				data = {}

				# Filling details about this power supply
				data["resource_name"] = enclName
				data["service_name"] = eachFanName
				data["severity"] = map_service_Status( fan["status"] )
				data["timestamp"] = str(datetime.now())
				data["description"] = fan["devicePresence"] + " *** " + fan["model"] + " *** " + fan["fanBayType"]
				data["correctiveAction"] = ". NA. "
				notify_nagios(data, nagiosDetails, 'SERVICE')
				sleep(1)
			# Process power statistics.
			process_power_stats(enclName, enclosure["uri"], oneview_client, nagiosDetails)
			sleep(1)

		start += count
		totalReceived += count
		if totalReceived >= total:
			break
	return ret

##################################################################
# Send port statistics of all interconnects to Nagios
#  
##################################################################
def send_port_stats_to_nagios(allPortStats, nagiosDetails):

	data = {}
	restartFlag = 0	
	allServices = get_all_services(nagiosDetails)
	# Process for each interconnects
	for portStats in allPortStats:
		interconnectName = trim_name(portStats["interconnectName"])

		# Get all services under perticular interconnect
		try:
			interconnectServices = allServices[interconnectName]
		except KeyError:
			# If no services under interconnects assign it to []
			interconnectServices = []

		logging.info("Processing port statistics for interconnect - "+str(interconnectName))
		
		# Get all linked ports
		linkedPorts = portStats["linkedPorts"]
		for port in linkedPorts:
			serviceName = 	interconnectName + "_stats_port_" + str(port["portName"])

			if not serviceName in interconnectServices:
				data["resource_name"] = str(interconnectName)
				data["service_name"] = serviceName
				create_service(data, nagiosDetails)
				restartFlag = 1
				#sleep(1)
					
		# Create all the entries and restart at end. Then update all the entries with descriptions. 
		# No need to restart Nagios for every service creation. 
		#
		if restartFlag == 1:
			retCode = 0
			retCode = apply_config_and_restart_nagios(nagiosDetails)
			if retCode != 0:
				logging.error("Error in applying config and restarting Nagios. Exiting python plugin. ")
				sys.exit(1)
			sleep(2)
			restartFlag = 0 # Nagios restarted. Reset the flag. 
			
		for port in linkedPorts:
			serviceName = 	interconnectName + "_stats_port_" + str(port["portName"])
			data["resource_name"] = str(interconnectName)
			data["service_name"] = serviceName
			
			# Filling details about port statistics to update the status
			data["severity"] = map_service_Status( port["members"]["Status"] )
			data["timestamp"] = str(datetime.now())
			description = "Status = " + str(port["members"]["Status"]) + " *** Speed = " + str(port["members"]["Speed"]) + " *** AdapterPort = " + str(port["members"]["adopterPort"])  + " *** IpAddress = " + str(port["members"]["macAddress"]) + " *** Received (bits) = " + str(port["members"]["IfInOctets"])  + " *** Transmitted (bits) = " + str(port["members"]["IfOutOctets"]) 
			data["description"] = description
			data["correctiveAction"] = ". NA. "
			notify_nagios(data, nagiosDetails, 'SERVICE')
			sleep(1)
			
		# Get all unlinked ports
		unlinkedPorts = portStats["unlinkedPorts"]
		for port in unlinkedPorts:
			serviceName = interconnectName + "_stats_port_" + port
			
			# Update if the service exist with the appropriate message
			if serviceName in interconnectServices:
				data["resource_name"] = str(interconnectName)
				data["service_name"] = serviceName
				
				# Filling details about port statistics to update the status
				data["severity"] = map_service_Status( 'WARNING' )
				data["timestamp"] = str(datetime.now())
				data["description"] = " Port Unlinked "
				data["correctiveAction"] = ""
				notify_nagios(data, nagiosDetails, 'SERVICE')
				sleep(1)

##################################################################
# Function which is to be called at the beginning to create hosts,
# services and host group in Nagios server - env  setup.
##################################################################
def create_infra_in_nagios(oneview_client, args, nagiosDetails):	
	oneViewIP = args["host"]
	# Create a string of host members - hosts mentioned in json file and servers detected
	masterHostGroup = ""
	
	# ---------------- ADDING SERVER HARDWARE TO NAGIOS ----------------
	# Query OneView appliance for its servers and create an entry for each of them in Nagios
	# URL = https://10.188.239.14/rest/server-hardware/?start=0&count=5
	print("\nAdding server hardware to Nagios...")
	URI = '/rest/server-hardware/'
	peripheralGroup = get_hardware_info(URI, oneview_client, oneViewIP, nagiosDetails)
	masterHostGroup += peripheralGroup
	

	# ---------------- ADDING ENCLOSURES TO NAGIOS ----------------
	# Query OneView appliance for its enclosures and create an entry for each of them in Nagios
	# URL = https://10.188.239.14/rest/enclosures/?start=0&count=5
	print("\nAdding enclosures to Nagios...")
	URI = '/rest/enclosures/'
	peripheralGroup = get_hardware_info(URI, oneview_client, oneViewIP, nagiosDetails)
	masterHostGroup += peripheralGroup
	sleep(1)
	
	update_enclosure_peripheral_info(URI, oneview_client, nagiosDetails)
	sleep(1)
	
	
	# ---------------- ADDING INTERCONNECTS TO NAGIOS ----------------
	# Query OneView appliance for its interconnects and create an entry for each of them in Nagios
	# URL = https://10.188.239.14/rest/interconnects/?start=0&count=5
	# 
	print("\nAdding interconnects to Nagios...")
	URI = '/rest/interconnects/'
	peripheralGroup = get_hardware_info(URI, oneview_client, oneViewIP, nagiosDetails)
	masterHostGroup += peripheralGroup
	

	# ---------------- ADDING SAS-INTERCONNECTS TO NAGIOS ----------------
	# Query OneView appliance for its interconnects and create an entry for each of them in Nagios
	# URL = https://10.188.239.14/rest/sas-interconnects/?start=0&count=5
	# 
	print("\nAdding sas-interconnects to Nagios...")
	URI = '/rest/sas-interconnects/'
	peripheralGroup = get_hardware_info(URI, oneview_client, oneViewIP, nagiosDetails)
	masterHostGroup += peripheralGroup
	

	# ---------------- ADDING LOGICAL-INTERCONNECTS TO NAGIOS ----------------
	# Query OneView appliance for its interconnects and create an entry for each of them in Nagios
	# URL = https://10.188.239.14/rest/logical-interconnects/?start=0&count=5
	# 
	print("\nAdding logical-interconnects to Nagios...")
	URI = '/rest/logical-interconnects/'
	peripheralGroup = get_hardware_info(URI, oneview_client, oneViewIP, nagiosDetails)
	masterHostGroup += peripheralGroup
	
	
	# Update status of OneView appliance to Nagios.
	#
	ovApplianceName = 'oneview-appliance_' + str(oneViewIP)

	# status = check_host_existence(ovApplianceName, nagiosDetails)
	hosts = get_all_hosts(nagiosDetails)
	if ovApplianceName not in hosts:
	# if status == 0:
		create_host(ovApplianceName, oneViewIP, nagiosDetails)
		logging.info("Appliance created - " + ovApplianceName)
		# Since it is only one host added here, restart only if the host is newly created. 
		apply_config_and_restart_nagios(nagiosDetails)
		sleep(2)

	
	applianceInfo = oneview_client.connection.get('/controller-state.json')
	logging.info("OneView appliance info :- " + str(applianceInfo))
	update_host_status(ovApplianceName, nagiosDetails, applianceInfo["state"])

	masterHostGroup += ovApplianceName
	print("\nMaster host group created with members - \n" + str(masterHostGroup)+"\n")
	sleep(1)	

	ovHostGroup = 'OneView' + '_' + str(oneViewIP)
	
	retVal = 0
	urlPrefix = 'http://'
	url = urlPrefix + nagiosDetails["nagiosHost"] + '/nagiosxi/api/v1/config/hostgroup'
	alias = args["alias"]

	params = {
		'pretty': '1',
		'apikey': nagiosDetails["apikey"]
	}

	data = {
		'hostgroup_name': ovHostGroup,
		'members': masterHostGroup,
		'alias': alias,
		'applyconfig': '1'
	}

	# Recreating the hostgroup freshly with host members.
	logging.info("Host group not existing. Creating it:")
	response = requests.post(url, params=params, data=data)
	retVal = response.status_code
	sleep(1)
	return retVal
