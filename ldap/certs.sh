#!/bin/bash

rm -f *.pem
rm -f *.der

users=("alice" "bob" "charlie" "dan")
for usr in ${users[@]}; do
  echo $usr
  openssl genrsa -out private-key-$usr.pem 2048
  openssl rsa -in private-key-$usr.pem -pubout -out public-key-$usr.pem
  openssl req -new -x509 -key private-key-$usr.pem -out cert-$usr.pem -days 360
  openssl x509 -outform DER -in cert-$usr.pem  -out $usr.der
done

ldapmodify -H ldap://localhost:389 -D uid=admin,ou=system -w secret -f certs.ldif
