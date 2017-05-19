#!/bin/bash

# Variables
dbname='vars'
dbuser='vars'

# Install postgres
echo '[+] Installing postgresql ...'
apt install postgresql postgresql-contrib -y > /dev/null

# Create system user and switch to that account
echo '[+] Creating system user for VARS ...'
addgroup --system $dbuser
adduser --system --ingroup $dbuser $dbuser

# Create postgresql user
echo ' [+] Creating postgresql user "vars" ...'
su postgres -c "createuser --createdb --pwprompt vars"

# Create the .pgpass file
read -e -s -p "Enter the password again so it can be added to .pgpass: " pswd
tmp="/home/$dbuser/.pgpass"
touch $tmp
chmod 0600 $tmp
echo "localhost:5432:vams:vams:$pswd" > $tmp

## Database Setup ##

# Create database
echo ' [+] Creating database ...'
sudo -u "$dbuser" createdb -O "$dbuser" "$dbname"

# Feed SQL script to psql
sudo -u "$dbuser" psql < $(pwd)/vars.db >> db-creation.out 2>&1

# Setup vars config
mkdir /etc/vars
cp `pwd`/vars.conf /etc/vars
chgrp "$dbuser" /etc/vars/vars.conf
chmod 644 /etc/vars/vars.conf
