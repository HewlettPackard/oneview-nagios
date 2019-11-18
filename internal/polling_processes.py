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

from common.utils import *
from ov_client.oneview_client import *
from nagios_client.nagios_client import *
import multiprocessing as mp

###########################################################################################
# Function which uses multiprocessing for updating hosts status, interconnects ports status 
# and enclosure power stats
###########################################################################################
def process_threads(oneview_client, nagiosDetails, hardwareCategory, refreshDuration=120):
	threadPool = mp.Pool(6)
	# Filtering interested hardwares for status update.
	hardwareCategory = [hardware for hardware in hardwareCategory if hardware not in ('sas-interconnects','logical-interconnects')]
	print('\nStarting polling processes!')
	while True:
		logging.info("Calling update enclosure powerstats in thread")
		threadPool.apply_async(update_power_stats, args=(oneview_client, nagiosDetails))

		logging.info("Calling update ports status in thread.")
		threadPool.apply_async(update_ports_status, args=(oneview_client, nagiosDetails))

		for hardware in hardwareCategory:
			logging.info("Calling update {} status in thread.".format(hardware))
			threadPool.apply_async(update_all_hosts_status, args=(oneview_client, nagiosDetails, hardware))

		sleep(refreshDuration)

	threadPool.close()
	threadPool.join()

###########################################################################################
# Function to update all ports status
# 
###########################################################################################
def update_ports_status(oneview_client, nagiosDetails):
	allPortStats = get_port_statistics(oneview_client)
	
	logging.info("Updating all ports status in Nagios.")
	ret = send_port_stats_to_nagios(allPortStats, nagiosDetails)

###########################################################################################
# Function to update enclosure power stats.
# 
###########################################################################################
def update_power_stats(oneview_client, nagiosDetails):
	# Get all enclosures
	enclosures = oneview_client.enclosures.get_all()
	# Update powerstats for each enclosure
	logging.info('Updating enclosure powerstats. ')
	for enclosure in enclosures:
		process_power_stats(enclosure["name"], enclosure["uri"], oneview_client, nagiosDetails)
		sleep(0.3)

###########################################################################################
# Function to update all hosts status.
# 
###########################################################################################
def update_all_hosts_status(oneview_client, nagiosDetails, hardwareCategory):
		logging.info('Updating {} status in Nagios.'.format(hardwareCategory))
		response = get_hosts_status(oneview_client,hardwareCategory)
		if response:
				for entity in response:
					hostname = entity['hostname']
					status = entity['status']
					corrAction = "State = " + entity['state']
					description = "Model = " + entity['model']
					update_host_status(hostname,nagiosDetails,status,corrAction,description)