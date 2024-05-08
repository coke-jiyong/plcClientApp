#!/bin/bash
# ! Do not modify the file. !

current_user=$(whoami)


if [ ! "$current_user" = "root" ]; then
	echo "Error: Please execute with root privileges."
	exit 1
fi

if [ "$#" -ne 1 ]; then
    echo "Usage: sh register-license.sh  <path_of_the_license_file>"
    exit 1
fi

license_file_path=$1
if [ ! -f "$license_file_path" ]; then
    echo "Error: License file does not exist in this path."
    exit 1
fi

license_destination_path="/opt/plcnext/otac/license/swidchauth.lic"

> "$license_destination_path"
cp "$license_file_path" "$license_destination_path"


echo "License file creation success. Please reboot to apply the license file."