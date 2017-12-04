#!/bin/bash

# Delete data from tables
sudo -u vars psql -c 'truncate emp,systems,tickets,vuln,affected,impact,dates,exploits,ref,cves,notes cascade;'

# Reset sequences
sudo -u vars psql -c 'alter sequence emp_empid_seq restart with 1;'
sudo -u vars psql -c 'alter sequence vuln_vulnid_seq restart with 1;'
sudo -u vars psql -c 'alter sequence systems_sysid_seq restart with 1;'
sudo -u vars psql -c 'alter sequence notes_noteid_seq restart with 1;'
