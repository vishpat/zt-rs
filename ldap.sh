#!/bin/bash

set -x

PWD=`pwd`
sudo docker stop ldap
sudo docker rm ldap
sudo docker run --name ldap -d -p 389:10389 -e APACHEDS_INSTANCE=ztrs -v $PWD/config.ldif:/bootstrap/conf/config.ldif:ro openmicroscopy/apacheds
