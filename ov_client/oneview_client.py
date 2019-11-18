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
from time import sleep
from datetime import datetime, timedelta

from common.parsing_apis import *
# from common.send_nrdp import *
from common.utils import *
	

# List of functions to be exported when including in other modules.
#__all__ = ['process_alert']

#def acceptEULA(con):
def acceptEULA(oneview_client):
	logging.info('acceptEULA')
	# See if we need to accept the EULA before we try to log in
	#con.get_eula_status()
	eula_status = oneview_client.connection.get_eula_status()
	try:
	#	if con.get_eula_status() is True:
	#		con.set_eula('no')
		if eula_status is True:
			oneview_client.connection.set_eula('no')
	except Exception as e:
		logging.error('EXCEPTION:')
		logging.error(e)

##################################################################
# Function to extract data from alert and process to send 
# msg to nagios server
##################################################################
def extract_data(msg, ovIpAddr, nagiosDetails):
	
	logging.debug("Entering - extract_data()")
	# Extract the fileds required for sending message update to Nagios server
	# Create an empty json object and fill in the required fields.
	data = {}

	logging.debug("Msg = " + str(msg))
	
	try:
		logging.info("Regular alert")
		## Changed serviceName to alertTypeId and not healthCategory.
		#
		# Get required host name to be done. 
		hostName = msg["resource"]["associatedResource"]["resourceName"]
		uri = msg["resource"]["uri"]
		
		# We would have created services for power supplies under each enclosure. 
		# If the alert belongs to power supply, then there is no need to create a new service. 
		# Redirecting the alert to the respective power supply
		#"resourceID": "/rest/v1/PowerSupply/4"
		#
		resourceID = msg["resource"]["resourceID"]
		healthCategory = msg["resource"]["healthCategory"]
		hardwareCategory = msg["resource"]["associatedResource"]["resourceCategory"]
		
		if (hardwareCategory == 'enclosures')and resourceID and (resourceID.split('/')[-2] == 'PowerSupply') and (healthCategory == 'Power'):
			bayNumber = msg["resource"]["resourceID"].split("/")[-1]
			serviceName = hostName + "_PowerSupplyBay_" + bayNumber
			serviceName = trim_name(serviceName)
			data["service_name"] = serviceName
			logging.info("Redirecting alert to service - "+ str(serviceName))
			
		else:
			tempAlertTypeID = msg["resource"]["alertTypeID"]
			serviceName = tempAlertTypeID.split('.')[-1]
			serviceName = trim_name(serviceName)
			
			# Append alert id
			serviceName = get_required_service_name(serviceName, uri)	
			data["service_name"] = serviceName
			
		logging.debug("Assigning timestamp")
		
		data["timestamp"] = msg["timestamp"]			
		logging.debug("Timestamp assigned")
		data["description"] = msg["resource"]["description"]
		data["description"] += "AlertTypeId: " + msg["resource"]["alertTypeID"]
		data["correctiveAction"] = msg["resource"]["correctiveAction"]
		severity = msg["resource"]["severity"]
		
		# Appending latest change log message if applicable
		# This might happen if an alert is cleared by the administrator or the person with privileges. 
		#
		change_log = msg["resource"]["changeLog"]
		if change_log:
			comments = change_log[-1]
			notes = comments["notes"]
			
			data["description"] += ". Notes: " + str(notes)
		print("Alert data:- " + data["description"])

	except Exception as e:
		logging.error("Not processing this alert as extraction failed. Returning.")
		logging.error(e)
		return

	hostName = trim_name(hostName)
	data["resource_name"] = hostName
	
	# Map the severity of oneview to that of nagios.
	data["severity"] = map_service_Status( severity )

	logging.debug("Event details to be sent to Nagios host :- " + str(data))
	logging.debug("hostName = " + str(hostName))
	logging.debug("serviceName = " + str(serviceName))
	logging.debug("ovIpAddr = " + str(ovIpAddr))
	logging.debug("nagiosDetails = " + str(nagiosDetails))
	
	
	# Notify nagios server about the alert
	serviceStat = check_service_existence(serviceName, hostName, ovIpAddr, nagiosDetails)
	if serviceStat != 0:
		logging.info("Node existing in Nagios. Notifying via NRDP")	
		
	else:
		# Service does not exist. Create it first and then update its status
		logging.info("Node not existing in Nagios. Creating it first and then notifying via NRDP :- " + str(serviceName))
		create_service(data, nagiosDetails)
		retCode = 0
		retCode = apply_config_and_restart_nagios(nagiosDetails)
		if retCode != 0:
			logging.error("Error in applying config and restarting Nagios. Exiting python plugin. ")
			sys.exit(1)
		sleep(2)

	
	notify_nagios(data, nagiosDetails, 'SERVICE')
	sleep(1)
	#logging.info("Leaving - extract_data()")


##################################################################
# Function which is to be called in callback() to process teh alert. 
# Alert should be from one of required host.
##################################################################
def process_alert(alert, ovIpAddr, nagiosDetails, input_alert_types, alert_hardware_type):
	logging.info("Processing Alert!")
	print("\nProcessing Alert...")
	try:
		hostCategory = alert["resource"]["associatedResource"]["resourceCategory"]
		alert_severity = alert["resource"]["severity"]
		# Proceed ahead only if the alert severity matches user input severity 
		if alert_severity.lower() in input_alert_types:
			# Process the alert if it is generated by one of required hostCategory only.
			#if hostCategory == 'server-hardware' or hostCategory == 'server-profile-templates' or hostCategory == 'interconnects' or hostCategory == 'server-profiles' or hostCategory == 'enclosures':
			if hostCategory in alert_hardware_type:
				logging.debug("Processing alert.")
				logging.info("alert_hardware_type-- " + str(alert_hardware_type[0]))
				extract_data(alert, ovIpAddr, nagiosDetails)
			else:
				logging.info("Host type unknown - " + str(hostCategory))
				logging.info("alert_hardware_type - " + str(alert_hardware_type[0]))
				sleep(1)

		else:
			logging.info("Alert severity = " + alert_severity)
			logging.info("Alert type does not match with user interest alert types - "+ ' '.join(input_alert_types))
	except Exception as e:
		logging.error("Parse error: Alert parsing failed.")
		logging.error(e)


		
##################################################################
# Process alerts onetime at the beginning based on user's input
#  
##################################################################
def process_alerts_one_time(oneview_client, args, nagiosDetails, input_alert_types, alert_hardware_type):
	# Process and update alerts onetime based on user input flag.
	#
	# Sample call:- onetimeEvents = oneview_client.connection.get('/rest/alerts?filter="created>=\'2015-05-12\'\"')
	
	print("\nAlerts to be processed onetime at the beginning.")
	allServices = get_all_services(nagiosDetails)
	onetimeAlertFlag = args["process_onetime_alerts"]	
	if onetimeAlertFlag.upper() == 'TRUE':
		onetimeEventsDuration = int(args["events_dated_from"])
		
		#  If users asks to process onetime events for more than 2 months, we reduce it to 1 month, 
		if not 1 <= onetimeEventsDuration <= 60:
			logging.info("Invalid range for onetime events processing - " + str(onetimeEventsDuration) + ". Making it 30.")
			onetimeEventsDuration = 30
			
		logging.info("Processing past event for " + str(onetimeEventsDuration) + " days.")
		sleep(1)
		
		day = datetime.today() - timedelta(days=onetimeEventsDuration)
		events_from = day.strftime('%Y-%m-%d')

		logging.info("Present date - " + str(datetime.today()))
		logging.info("Processing events from - " + str(events_from))
		
		onetimeURI = '/rest/alerts?filter="created>=\'' + str(events_from) + '\'\"'
		
		try:
			onetimeEvents = oneview_client.alerts.get(onetimeURI)
			allEvents = onetimeEvents["members"]
		except Exception as e:
			logging.error("Failed to get alerts from oneview at the beginning.")
			logging.error(e)			
			return 1
			
		alerts =[]
		for alert in allEvents:
			
			alert_severity = alert["severity"]
			hostCategory = alert["associatedResource"]["resourceCategory"]
			if (alert_severity.lower() in input_alert_types) and (hostCategory in alert_hardware_type):
				data = {}
				tempAlertTypeID = alert["alertTypeID"]
				serviceName = tempAlertTypeID.split('.')[-1]
				hostName = alert["associatedResource"]["resourceName"]
				hostName = trim_name(hostName)
				data["resource_name"] = hostName
				uri = alert["uri"]
				
				# Trim the service name with unwanted characters.
				serviceName = trim_name(serviceName)				
				
				# Append alert id
				serviceName = get_required_service_name(serviceName, uri)	
				data["service_name"] = serviceName
				data["timestamp"] = alert["eTag"]
				data["description"] = alert["description"]
				data["description"] += "AlertTypeId: " + alert["alertTypeID"]
				data["correctiveAction"] = alert["correctiveAction"]
				severity = alert["severity"]
				
				# Appending latest change log message if applicable
				# This might happen if an alert is cleared by the administrator or the person with privileges. 
				#
				change_log = alert["changeLog"]
				if change_log:
					comments = change_log[-1]
					notes = comments["notes"]
					data["description"] += " Notes: " + str(notes)
				# Map the severity of oneview to that of nagios.
				data["severity"] = map_service_Status( severity )				
				alerts.append(data)
				
		restartFlag = 0
		try:
			for alert in alerts:
				# Check if the service already exists
				if alert['service_name'] not in allServices[alert['resource_name']]:
					logging.debug("alert not existing in Nagios. Creating it first and then notifying via NRDP :- " + str(serviceName))
					# Create service for alert.
					create_service(alert, nagiosDetails)
					restartFlag = 1
				sleep(0.5)
		except Exception as e:
			logging.error("Failed to create one time alert \"{}\", Exiting...".format(alert['service_name']))
			sys.exit(e)
		
		# Restrat Nagios after creating services if the restartFlag is set.
		if restartFlag == 1:		
			retCode = apply_config_and_restart_nagios(nagiosDetails)
			if retCode != 0:
				logging.error("Error in applying config and restarting Nagios. Exiting python plugin. ")
				sys.exit(1)
			sleep(1)
			restartFlag = 0
			
		for alert in alerts:
			# Update alert service
			logging.debug("notifying via NRDP :- {} ".format(serviceName))
			notify_nagios(alert, nagiosDetails, 'SERVICE')
			logging.debug("One time alert = " + str(alert))
			sleep(0.5)
		print("One time alerts processed.")
	else:
		print("Alerts not being processed at the beginning. Flag not set to true.")
	
	return 0

	
##################################################################
# Process ports status 
#  
##################################################################
def get_port_statistics(oneview_client):

	data = []

	# Get all interconnects
	interconnects = oneview_client.interconnects.get_all()

	# parse inerconnects one by one
	for interconnect in interconnects:
		interconnectName = interconnect['name']
		linkedPorts = []
		unlinkedPorts = []
		# Get all ports in an interconnect
		interconnect_ports = oneview_client.interconnects.get_ports(interconnect['uri'])

		# get port statistics
		for port in interconnect_ports:
			if port['portStatus'] == "Linked":
				portName = port['portName']
				members = {}
				members['Status'] = port['status']
				advanced_stats = oneview_client.interconnects.get_statistics(interconnect['uri'],portName)
				if port['operationalSpeed']:
					members['Speed'] = port['operationalSpeed']
				else:
					members['Speed'] = None
				if port['neighbor']:
					if port['neighbor']['remotePortId']:
						members['adopterPort'] = port['neighbor']['remotePortId']
					else:
						members['adopterPort'] = None
					if port['neighbor']['remoteMgmtAddress']:
						members['macAddress'] = port['neighbor']['remoteMgmtAddress']
					else:
						members['macAddress'] = None
				else:
					 members['adopterPort'] = None
					 members['macAddress'] = None
				
				if advanced_stats and advanced_stats['commonStatistics']:
					members['IfInOctets'] = advanced_stats['commonStatistics']['rfc1213IfInOctets']
					members['IfOutOctets'] = advanced_stats['commonStatistics']['rfc1213IfOutOctets']
				else:
					members['IfInOctets'] = None
					members['IfOutOctets'] = None
				linkedPorts.append({'portName':portName,'members': members})
			elif port['portStatus'] == "Unlinked":
				unlinkedPorts.append(port['portName'])
		data.append({'interconnectName' : interconnectName, 'linkedPorts' : linkedPorts ,'unlinkedPorts' : unlinkedPorts})
	return data

##################################################################
# Get the host's status to update in Nagios when required.
#  
##################################################################
def get_hosts_status(oneview_client,hostCategory):
	hosts_status = []
	if hostCategory == "interconnects":
		#Get all interconnects
		response  = []
		interconnects = oneview_client.interconnects.get_all()
		# Extending the list with interconnects
		response.extend(interconnects)
		# TODO - To be validated in DCS
		sas_interconnects = oneview_client.sas_interconnects.get_all()
		if sas_interconnects:
			# Extending the list with sas-interconnects
			response.extend(sas_interconnects)
		logical_interconnects = oneview_client.logical_interconnects.get_all()
		if logical_interconnects:
			# Extending the list with logical-interconnects
			response.extend(logical_interconnects)
	if hostCategory == 'enclosures':
		# Get all enclosures
		response = oneview_client.enclosures.get_all()
	if hostCategory == 'server-hardware':
		# Get all server hardwares
		response = oneview_client.server_hardware.get_all()
	for member in response:
		data = {}
		#Construct data body
		hostName = trim_name(member['name'])
		data['hostname'] = hostName.replace(' ','_')
		data['status'] = member['status']
		data['state'] = member['state']
		try:
		# if member['category'] == 'logical-interconnects':
			data['model'] = member['model']
		# else:
		except KeyError:
			data['model'] = 'N.A'
		hosts_status.append(data)
	return hosts_status
	

	
