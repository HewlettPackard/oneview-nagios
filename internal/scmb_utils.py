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

import os
import ssl
import amqplib.client_0_8 as amqp

from common.utils import *

##################################################################
# Initialize certs dir.
##################################################################
def initialize_certs():
	# Create certs directory for storing the OV certificates
	certpath=os.getcwd() + os.sep + "certs"
	if not os.path.exists(certpath):
			os.makedirs(certpath)

##################################################################
# Generate RabbitMQ certs.
##################################################################
def genRabbitCa(oneview_client):
	logging.info('genRabbitCa')
	try:
		certificate_ca_signed_client = {
			"commonName": "default",
			"type": "RabbitMqClientCertV2"
		}
		oneview_client.certificate_rabbitmq.generate(certificate_ca_signed_client)
	except Exception as e:
		logging.warning("Error in generating RabbitMQCa.")
		logging.warning(e)

##################################################################
# Get RabbitMQ CA cert
##################################################################
def getCertCa(oneview_client, host):
	logging.info('getCertCa')
	cert = oneview_client.certificate_authority.get()
	ca = open('certs/' + host + '-caroot.pem', 'w+')
	ca.write(cert)
	ca.close()

##################################################################
# Get RabbitMQ KeyPair.
##################################################################			
def getRabbitKp(oneview_client, host):
	logging.info('getRabbitKp')
	try:
		cert = oneview_client.certificate_rabbitmq.get_key_pair('default')
	except Exception as e:
		if e.msg == 'Resource not found.':
			genRabbitCa(oneview_client)
			cert = oneview_client.certificate_rabbitmq.get_key_pair('default')
	ca = open('certs/' + host + '-client.pem', 'w+')
	ca.write(cert['base64SSLCertData'])
	ca.close()
	ca = open('certs/' + host + '-key.pem', 'w+')
	ca.write(cert['base64SSLKeyData'])
	ca.close()

##################################################################
# Function to stop SCMB.
# This code written based on info provided by https://www.rabbitmq.com/consumer-cancel.html
##################################################################
def stopSCMB(host):
	logging.info("stopSCMB: stopping SCMB")

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
	ch.queue_bind(qname, EXCHANGE_NAME, 'scmb.#')

	# Send a message to end this queue
	# basic_cancel(msg.consumer_tag)
	ch.basic_cancel(None, None)
	ch.close()