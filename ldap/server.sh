#!/bin/bash

set -x

PWD=`pwd`
sudo docker stop ldap
sudo docker rm ldap
sudo docker run --name ldap -d -p 389:10389 openmicroscopy/apacheds

sleep 10
ldapadd -H ldap://localhost:389 -D uid=admin,ou=system -w secret -f config.ldif
