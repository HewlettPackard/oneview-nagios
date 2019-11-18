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

# Nagios service status permitted as follows: OK = 0, Warning = 1, Critical = 2, Unknown = 3; 
# For ports, status DISABLED = Warning
#
serviceStatusMap = {'OK':0, 'WARNING':1, 'CRITICAL':2, 'UNKNOWN':3, 'DISABLED':1}

# Nagios statuses permitted : UP = 0, DOWN = 1, UNREACHABLE = 2; 
# Mapping Host statuses from Oneview onto Nagios as follows: 
# OK - UP, WARNING = UP, CRITICAL = DOWN, UNKNOWN = UNREACHABLE, DISABLED = DOWN.
#
nodeStatusMap = {'OK':0, 'WARNING':0, 'CRITICAL':1, 'UNKNOWN':2, 'DISABLED':1}
##################################################################
# Function to append the service tag to the end of service name. 
##################################################################
def get_required_service_name(service_name, uri):
	
	temp = uri.split('/')
	if temp:
		id = temp[-1]
		service_name += '_' + str(id)
		service_name = service_name.replace(" ", "_")
		logging.info("Service name :- " + service_name)
	else:
		logging.error('No service id: URI - ' + str(uri))
			
	return service_name

##################################################################
# Map oneview alert status of service to nagios status
##################################################################
def map_service_Status(status):
	
	# Nagios service status : OK = 0, Warning = 1, Critical = 2, Unknown = 3
	# {'OK':0, 'WARNING':1, 'CRITICAL':2, 'UNKNOWN':3}
	
	if status.upper() in serviceStatusMap:
		id = serviceStatusMap[status.upper()]
	else:
		logging.error("Alert status received :" + str(status) + ". Cannot find service status. Assigning to unknown.")
		id = 3
		logging.error("Alert status received : " + str(status) + ". Mapped to id = %d (Unknown) ", id)
		
	return id


##################################################################
# Map oneview alert status of node to nagios status
##################################################################
def map_node_status(status):
	# Nagios host status - {'OK':0, 'WARNING':0, 'CRITICAL':1, 'UNKNOWN':2, 'DISABLED':1}
		
	if status.upper() in nodeStatusMap:
		id = nodeStatusMap[status]
	else:
		id = 2
		logging.error("Cannot find node status - Received : " + str(status) + ". Mapped to id = %d (Unreachable) ", id)
	
	return id
	
	
