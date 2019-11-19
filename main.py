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

import sys
if sys.version_info < (3, 6):
	print('Incompatible version of Python, Please use Python ver 3.6 and above..!')
	sys.exit(1)

import argparse
import json
import ssl
import logging

import multiprocessing as mp
from time import sleep
from hpOneView.oneview_client import OneViewClient
from functools import partial
import amqplib.client_0_8 as amqp
from ov_client.oneview_client import *
from nagios_client.nagios_client import *
from common.send_nrdp import *
from internal.polling_processes import *
from internal.scmb_utils import *


# Setting logging level of "requests" module
# This is to avoid info and debug messages of requests module being printing b/w application log messages. 
#
logging.getLogger("amqp").setLevel(logging.WARNING)

# Global variable for callback
config = {}

def callback(channel, msg):
	global config
	logging.debug("msg.delivery_tag: %s", msg.delivery_tag)
	logging.debug("msg.consumer_tag: %s", msg.consumer_tag)
		
	# ACK receipt of message
	channel.basic_ack(msg.delivery_tag)

	# Convert from json into a Python dictionary
	content = json.loads(msg.body)
	
	# Add a new attribute so that the server side can recognize from which appliance it is this message comes from.
	content['messageHost'] = config['oneViewIP'];
	# headers = {"Content-Type" : "application/json", "Accept" : "application/json"}

	logging.debug("CONTENT %s", content)
	## Processing alert via thread pool. 
	#
	mpThreadPool.apply_async(process_alert, args = (content, config['oneViewIP'], config['nagiosDetails'], \
		config['inputAlertTypes'], config['alertHardwareTypes']))
	sleep(0.1)		
	
	# Cancel this callback
	if msg.body == 'quit':
		channel.basic_cancel(msg.consumer_tag)

def recv(host, route):
	logging.info("recv - Entry %s", route)

	# Create and bind to queue
	EXCHANGE_NAME = 'scmb'
	dest = host + ':5671'

	# Setup our ssl options
	ssl_options = ({'ca_certs': 'certs/' + host + '-caroot.pem',
					'certfile': 'certs/' + host + '-client.pem',
					'keyfile': 'certs/' + host + '-key.pem',
					'cert_reqs': ssl.CERT_REQUIRED,
					'ssl_version' : ssl.PROTOCOL_TLSv1_1,
					'server_side': False})

	logging.info(ssl_options)

	# Connect to RabbitMQ
	conn = amqp.Connection(dest, login_method='EXTERNAL', ssl=ssl_options)
	
	ch = conn.channel()
	qname, _, _ = ch.queue_declare()
	routeArray = route.split(';')
	for each in routeArray:
		logging.info("SCMB bind to " + each)
		ch.queue_bind(qname, EXCHANGE_NAME, each)
	ch.basic_consume(qname, callback=partial(callback, ch))
	print("\nConnection established to SCMB. Listening for alerts...\n")
	# Start listening for messages
	while ch.callbacks:
		ch.wait()

	ch.close()
	conn.close()
	logging.info("recv - Exit")


##################################################################
# Main function.
# 
##################################################################
def main():

	global config
	
	parser = argparse.ArgumentParser(add_help=True, description='Usage')
	parser.add_argument('-i','--input_file',dest='input_file', required=True,
						help='Json file containing oneview and nagios details')
		
	# Check and parse the input arguments into python's format
	inputFile = parser.parse_args()
	
    # Parsing file for details  
	with open(inputFile.input_file) as data_file:	
		inputConfig = json.load(data_file)
	
    # Get the logging level and refresh duration
	loggingLevel = inputConfig["logging_level"].upper() 
	refreshDuration = inputConfig['stats_refresh_duration']
	
	try:
		# Validate the data in the OneView and Nagios config files.
		oneViewDetails = inputConfig["oneview_config"]
		nagiosDetails = inputConfig["nagios_config"]
	
	except Exception as e:
		# We will not be able to log this message since logging is not yet initialized, hence printing
		print("Error in config files. Check and try again.")
		print(e)
		sys.exit(1)

	# Initialize logging
	initialize_logging(oneViewDetails['host'], loggingLevel)

	# Valid alert types sent by Oneview. This is used to compare the user input "alert_type" from oneview.json file
	alertTypes = ['Ok','Warning','Critical','Unknown']
	hardwareTypes = ['server-hardware','enclosures','interconnects','sas-interconnects','logical-interconnects']

	# Validate input file
	ret = validate_input_config(oneViewDetails, nagiosDetails, hardwareTypes, alertTypes)
	if ret == 0:
		logging.info("Successfully validated input file")

	if not loggingLevel:
		logging.info("\"logging_level\" is not provided, taken\"WARNING\" as default.")
	if not refreshDuration:
		logging.info("\"stats_refresh_duration\" is not provided, taking 120s as default.")
		refreshDuration = '120'


	# append global dict with required values
	config['oneViewIP'] = oneViewDetails['host']
	config['nagiosDetails'] = nagiosDetails
	config['alertHardwareTypes'] = oneViewDetails["alert_hardware_category"].split(':')
	inputAlertTypes = oneViewDetails["alert_type"].split(':')
	config['inputAlertTypes'] = [x.lower() for x in inputAlertTypes] # User interested alert types


	# Logging input details.
	logging.info('OneView args: host = %s, alias = %s, route = %s, action = %s, process_onetime_alerts = %s, events_dated_from = %s', \
		oneViewDetails["host"], oneViewDetails["alias"], oneViewDetails["route"], oneViewDetails["action"], \
		oneViewDetails["process_onetime_alerts"], oneViewDetails["events_dated_from"])
		
	logging.info('Nagios args: nagiosHost = %s ', nagiosDetails["nagiosHost"])

	# Esatblish connection to OneView
	if oneViewDetails["action"] == "start":
		logging.debug("Attempting to establish connection with OV SCMB")
		logging.debug("Arguments: " + str(oneViewDetails))

		ovConfig = {
			"ip": oneViewDetails["host"],
			"credentials": {
				"userName": oneViewDetails["user"],
				"authLoginDomain": oneViewDetails["authLoginDomain"],
				"password": oneViewDetails["passwd"]
			}
		}

		try:
			oneview_client = OneViewClient(ovConfig)
			acceptEULA(oneview_client)
			logging.info("Connected to OneView appliance : {}".format(oneViewDetails["host"]))
		#except HPOneViewException as e:
		except Exception as e:
			#logging.error("Error connecting to appliance: msg: %s", e.msg)
			logging.error("Error connecting to appliance. Check for OneView details in input json file.")
			logging.error(e)
			sys.exit(1)

		# Create Infrastructure in Nagios server
		create_infra_in_nagios(oneview_client, oneViewDetails, nagiosDetails)
		logging.info("Infra created if not present already. Processing alerts now.")
		sleep(1)
		
		
		# Process alerts onetime at the beginning based on user's input in json file
		ret = process_alerts_one_time(oneview_client, oneViewDetails, nagiosDetails, config['inputAlertTypes'], config['alertHardwareTypes'])
		if (ret != 0):
			print("One-time processing of alerts failed.")

		# Create certs directory for storing the OV certificates
		initialize_certs()

		# Download the certificates
		getCertCa(oneview_client, oneViewDetails["host"])
		getRabbitKp(oneview_client, oneViewDetails["host"])
		
		# Creating new process for polling processes
		pollProcess = mp.Process(target=process_threads, args=(oneview_client, nagiosDetails, config['alertHardwareTypes'], int(refreshDuration), ))
		pollProcess.start()

		# Start listening for messages.
		recv(oneViewDetails["host"], oneViewDetails["route"])
		
		# Join Process pollProcess.
		pollProcess.join()

		print("Closing Thread Pool!")
		mpThreadPool.close()
		# Join the Pool
		mpThreadPool.join()
		

	elif oneViewDetails["action"] == "stop":
		# Stop SCMB connection for this appliance
		logging.info("TODO: stop action implementation")
		# stopSCMB(oneViewDetails.host)
	else:
		# Do nothing and exit
		logging.error("Missing or invalid option for action in oneview.json; It should be start/stop.")
		print("Missing or invalid option for action in oneview.json; It should be start/stop.")
		

if __name__ == '__main__':
	## Create a thread pool with 5 worker threads
	#
	mpThreadPool = mp.Pool(5)
	sleep(0.1)
	
	sys.exit(main())
