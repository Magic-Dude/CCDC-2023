#!/bin/bash

# Path to the user list and passwd file
userList="users.txt"
passwdFile="/etc/passwd"

# Read each user from the /etc/passwd file
while IFS=: read -r username _ _ _ _ _ shell; do
    # Check if the user's shell is /bin/bash
    if [[ "$shell" == "/bin/bash" ]]; then
        # Assume the user is not in the list initially
        found=0
        # Check against each user in the users.txt file
        while IFS= read -r listedUser; do
            if [[ "$username" == "$listedUser" ]]; then
                # User is found in the list, no need to check further
                found=1
                break
            fi
        done < "$userList"
        # If the user is not found in the list, print the username
        if [[ $found -eq 0 ]]; then
            echo "$username"
        fi
    fi
done < "$passwdFile"