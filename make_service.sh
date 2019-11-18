#!/bin/bash
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

key="$1"

case $key in
    -n|--name)
    service_name="$2"
    ;;

    -h|--help)
    echo
    echo Usage: sh make_service.sh [Optiopns...] [Values...]
    echo        -n, --name  Name of the service for plugin
    echo
    ;;

    *)
    echo Invalid option recieved!
    echo
    echo Usage: sh make_service.sh [Optiopns...] [Values...]
    echo "       -n, --name  (Name of the service for plugin)"
    echo
    exit 1
    ;;
esac

dot_service=".service"

if test ${service_name#*$dot_service} != $service_name
then
        unit_file=$service_name
else
        unit_file="$service_name.service"
fi

if [ $? -ne 0 ]
then
    echo Error occurred! Failed to create service, Please check.
    exit 1
fi

# Create systemd service unit file
cp ./internal/service_template /etc/systemd/system/$unit_file

# Repalce PWD with working Dir
sed -i 's@PWD@'"$PWD"'@g' /etc/systemd/system/$unit_file

# Reload daemon
systemctl daemon-reload
echo
echo Service \"$service_name\" successfully created
echo

