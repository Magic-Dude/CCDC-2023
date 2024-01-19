#!/bin/bash

getent passwd | awk -F: '$3 > 1000 {print $1}' | while read -r username; do
	echo "Deleting user: $username"
	sudo userdel -r "$username"
done

