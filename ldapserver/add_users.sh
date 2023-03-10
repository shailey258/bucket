#!/bin/bash

#ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin -H ldap:// -f users.ldif
ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin -H ldap://localhost:389 -f users3.ldif

