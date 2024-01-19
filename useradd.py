import os

num_of_users = int(input("How many users do you want:"))

for i in range(num_of_users):

	username = f"user{i+1}"

	#Sets the account with no password
	addusercmd = f"sudo useradd user{i+1}"
	
	# Delete the user's password to make it disabled
	no_password = f"sudo passwd -d user{i+1}"

	os.system(addusercmd)
	os.system(no_password)