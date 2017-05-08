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

# Create employee table
#echo ' [+] Creating employee table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table emp ( empid serial PRIMARY KEY, firstname varchar(50) NOT NULL, lastname varchar(50) NOT NULL, email text NOT NULL );\" -d $dbname"

# Create vuln table
#echo ' [+] Creating vulnerability table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table vuln ( vulnid serial PRIMARY KEY, vulnname text NOT NULL, cve varchar(25), finder integer REFERENCES emp (empid) NOT NULL, initiator integer REFERENCES emp (empid) NOT NULL, summary text NOT NULL, test text NOT NULL, mitigation text NOT NULL );\" -d $dbname"

# Create ticket table
#echo ' [+] Creating ticket table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table tickets ( vulnid integer REFERENCES vuln (vulnid), ticket integer NOT NULL, PRIMARY KEY (vulnid, ticket) );\" -d $dbname"

# Create ref table
#echo ' [+] Creating reference table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table ref ( vulnid integer REFERENCES vuln (vulnid), url text NOT NULL, PRIMARY KEY (vulnid, url) );\" -d $dbname"

# Create impact table
#echo ' [+] Creating impact table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table impact ( vulnid integer REFERENCES vuln (vulnid) PRIMARY KEY, cvss integer NOT NULL, cvsslink text, corpscore integer NOT NULL );\" -d $dbname"

# Create dates table
#echo ' [+] Creating dates table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table dates ( vulnid integer REFERENCES vuln (vulnid) PRIMARY KEY, published date, initiated date NOT NULL, mitigated date );\" -d $dbname"

# Create exploits table
#echo ' [+] Creating exploits table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table exploits ( vulnid integer REFERENCES vuln (vulnid) PRIMARY KEY, exploitable boolean, exploit text );\" -d $dbname"

# Create systems table
#echo ' [+] Creating systems table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table systems ( sysid serial PRIMARY KEY, sysname text NOT NULL, description text NOT NULL );\" -d $dbname"

# Create affected table
#echo ' [+] Creating affected table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table affected ( vulnid integer REFERENCES vuln (vulnid), sysid integer REFERENCES systems (sysid), PRIMARY KEY (vulnid, sysid) );\" -d $dbname"

# Create docs table
#echo ' [+] Creating documents table ...'
#su $dbuser -c "psql $dbuser -h localhost -c \"create table docs ( vulnid integer REFERENCES vuln (vulnid), docpath text NOT NULL, dockey text NOT NULL, PRIMARY KEY (vulnid, docpath) );\" -d $dbname"
