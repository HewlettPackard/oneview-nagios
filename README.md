# OneView and Nagios Integration for Hardware Infrastructure Monitoring

**Problem Statement**

Some of our Synergy customers in EMEA were looking for hardware monitoring solution through OneView and Nagios. Today, they are using Nagios to monitor their compute infrastructure using OS based agents and SNMP traps. They don't have a solution to monitor enclosure status, interconnects status, ports status, power consumption and ports statistics and utilization data. This gap was delaying their ability to resolve the outages and infrastructure failures.

**Solution design**

To address their needs, we developed a plugin using Python which collects health status and utilization statistics for physical infrastructure including servers and shared resources like enclosures and virtual connects. Plugin does necessary processing of collected data before posting to Nagios over NRDP for possive monitoring. For utilization statistics, plugins does polling of OneView using REST API because OneView metrics API ( MSMB ) is not providing the utilization for ports level. The plugin has intelligence to determine whether to create new entry or update an existing entry in Nagios. Plugin is designed to handle processing of alerts data in parallel by running concurrent threads. There will be one plugin instance required for each OneView appliance.

This solution can be seamlessly extended to monitor all infrastructure supported by HPE OneView.


**End outcome**

Once the data is posted to Nagios, user can view health status and utilization data in Nagios UI. If there are more than one OneView posting data to Nagios, data is grouped under respective OneView group within Nagios. The solution we developed is more generic monitoring solution and doesn't limit to any particular customer. The plugin can be deployed on any Linux based server or a docker container.


## Getting Started

System requirements - Centos7 machine for plugin deployment, Nagios XI server and OneView appliance.

### Prerequisites and Installing the components of test environment

Setting up the Nagios XI server
```
1. Create a fresh Centos 7 VM with minimal install or server with GUI. 
2. Install Nagios XI in a fresh clean machine. The machine should be able to access the internet. Follow the commands below. 

	$ yum update -y
	$ yum install firewalld wget -y (if Centos7 is minimal install - not required of server with GUI)
	$ cd /tmp
	$ wget https://assets.nagios.com/downloads/nagiosxi/xi-latest.tar.gz
	$ tar xzf xi-latest.tar.gz
	$  cd nagiosxi
	$ ./fullinstall
3. Nagios server web UI :- http://<Nagios server IP address>/nagiosxi/ 
	=> username/password is setup. You can change the password. 

4. Configuring secret token for NRDP:-
	Modify/add the secret token in the file - /usr/local/nrdp/server/config.inc.php as below:-
		$ cfg['authorized_tokens'] = array("MY_SECRET_TOKEN");
	
	Replace MY_SECRET_TOKEN with the intented token (Double quotes to remain).
		eg: $ cfg['authorized_tokens'] = array("privatetoken");
		
	Test NRDP " http://<Nagios IP address>/nrdp/ " with the secret token as modified earlier. 
	
5. Noting down apikey:-
	Upon logging to webUI, click on username (usually nagiosadmin) and then copy the apikey below email address. 
```

Setting up the Linux  machine with python3.6 and relevant packages. 
```
1. To setup python3.6
	Step 1: Open a Terminal and add the repository to your Yum install.
	$ sudo yum install -y https://centos7.iuscommunity.org/ius-release.rpm
	
	Step 2: Update Yum to finish adding the repository.
	$ sudo yum update
	
	Step 3: Download and install Python.		
	$ sudo yum install -y python36u python36u-libs python36u-devel python36u-pip
	
	Step 4: Once these commands are executed, simply check if the correct version of Python has been installed by executing the following command:
	$ python3.6 -V
	
	
2. To setup relevant python3.6 modules. 
	Step1: The required python3.6 modules and their versions are mentioned in the file requirements.txt; Install them using the below command.
	$ pip3 install -r requirements.txt
```
Setting up the OneView appliance. 
```
1. Download and install the latest version of OneView appliance from the source link - https://www.hpe.com/in/en/resources/integrated-systems/oneview-trial.html
2. Add a server hardware via enclosure or iLO.
```

### Files to be modified - ***config/input_config_nagios.json***.

Edit the following information:
```
1. OneView details - ipaddress, username, password, process_onetime_alerts flag, events dated from for onetime events alerting to Nagios, polling time, alert type and alert hardware category.
2. Nagios XI details - ipaddress, secrettoken and apikey
```

The next section mentions about how to do a dry run of the setup.

## Running the tests

Our python plugin can be deployed in one of the following 3 ways:
```
1. 	As a “systemd” service
2.	As a standalone script
3.	As a docker container. 
```

> Ensure OneView appliance is up and running. Ping test the OV appliance to see if it is reachable. 

`$ ping <OV IP Address>`

> Ensure Nagios service in server is up and running. Type the following command to see the status of nagios service. 

`$ service nagios status`


## Deployment

> Modify inputs in file ***config/input_config_nagios.json***.

### To run as systemd service

Execute as follows:-
```
$ sudo sh make_service.sh --name <SERVICE_NAME>
$ sudo service <SERVICE_NAME> start
```

### To run as docker container

Follow [install docker](https://docs.docker.com/install/linux/docker-ee/centos/) to setup docker engine.

```
1. Edit ***docker_env*** files according to your environment.

2. Build docker image 

	If you are behind proxy server

	$ sudo docker build --build-arg http_proxy=http://<proxy_server>:<port> -t oneview-nagios-plugin .

	Else

	$ sudo docker build -t oneview-nagios-plugin .

3. Start docker container
	
	$ sudo docker run -d -v $PWD:/plugin --env-file docker_env oneview-nagios-plugin python main.py -i config/input_config_nagios.json
	
```

### To run as standalone script

Execute as follows:-

```
$ python3.6 main.py -i config/input_config_nagios.json
```

### To see logs

`$ tail -f logs/OneViewNagios_<OneViewIP>.log`

	
## Built With

* Nagios XI - The monitoring tool used.
* OneView - Appliance which is used to configure and manage the servers
* Python3.6 - Scripting language used
* Docker - For containerization


## Versioning

We use [GitHub](http://github.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **GSE Team, Bangalore** 

See also the list of [contributors](https://github.hpe.com/GSE/oneview-nagios/graphs/contributors) who participated in this project.

## License

(C) Copyright (2018) Hewlett Packard Enterprise Development LP

## Acknowledgments

