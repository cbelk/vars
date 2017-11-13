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

# Get password for new postgres user
matched=false
while ! $matched; do
    read -e -s -p "Enter the password for the VARS database user: " p1
    echo ""
    read -e -s -p "Enter it again: " p2
    echo ""
    if [ "$p1" == "$p2" ]; then
        pswd="$p1"
        matched=true
    else
        echo "[-] Passwords did not match"
    fi
done

# Create postgresql user
echo ' [+] Creating postgresql user "vars" ...'
su postgres -c "createuser --createdb vars"
tq="ALTER USER vars WITH PASSWORD '"$pswd"';"
su postgres -c "psql -c \"$tq\""

# Create the .pgpass file
tmp="/home/$dbuser/.pgpass"
touch $tmp
chmod 0600 $tmp
echo "localhost:5432:$dbname:$dbuser:$pswd" > $tmp

## Database Setup ##

# Create database
echo ' [+] Creating database ...'
sudo -u "$dbuser" createdb -O "$dbuser" "$dbname"

# Feed SQL script to psql
sudo -u "$dbuser" psql < $(pwd)/vars.db >> db-creation.out 2>&1

# Setup vars config
mkdir /etc/vars
#cp `pwd`/vars.conf /etc/vars
echo -e "{\n\t\"user\" : \"$dbuser\",\n\t\"pass\" : \"$pswd\",\n\t\"name\" : \"$dbname\",\n\t\"host\" : \"localhost\",\n\t\"port\" : \"5432\"\n}" > /etc/vars/vars.conf
chgrp "$dbuser" /etc/vars/vars.conf
chmod 640 /etc/vars/vars.conf
