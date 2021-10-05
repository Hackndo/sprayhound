# SprayHound

[![PyPI version](https://d25lcipzij17d.cloudfront.net/badge.svg?id=py&type=6&v=0.0.3&x2=0)](https://pypi.org/project/sprayhound/) [![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)


![Example](https://raw.githubusercontent.com/Hackndo/sprayhound/master/asssets/example.gif)

Python library to safely password spray in Active Directory, set pwned users as owned in Bloodhound and detect path to Domain Admins


This library uses [python-ldap](https://www.python-ldap.org/en/python-ldap-3.3.0/) project for all LDAP operations.

| Chapters                                     | Description                                             |
|----------------------------------------------|---------------------------------------------------------|
| [Requirements](#requirements)                | Requirements to install sprayhound                      |
| [Warning](#warning)                          | Before using this tool, read this                       |
| [Installation](#installation)                | Installation instructions                               |
| [Usage](#usage)                              | Usage and command lines examples                        |

## Requirements

* Python >= 3.6

## Warning

Only default domain policy is checked for now. If custom GPO is used for password policy, it won't be detected. That's some work in progress.


## Installation

### From pip

```bash
python3 -m pip install sprayhound
```

### From source

```bash
sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev
git clone git@github.com:Hackndo/sprayhound.git
cd sprayhound
python3 setup.py install
```

## Usage

### Parameters

```bash
$ sprayhound -h

usage: sprayhound [-h] [-u USERNAME] [-U USERFILE]
                  [-p PASSWORD | --lower | --upper] [-t THRESHOLD]
                  [-dc DOMAIN_CONTROLLER] [-d DOMAIN] [-lP LDAP_PORT]
                  [-lu LDAP_USER] [-lp LDAP_PASS] [-lssl]
                  [-lpage LDAP_PAGE_SIZE] [-nh NEO4J_HOST] [-nP NEO4J_PORT]
                  [-nu NEO4J_USER] [-np NEO4J_PASS] [--unsafe] [--force]
                  [--nocolor] [-v]

sprayhound v0.0.1 - Password spraying

optional arguments:
  -h, --help            show this help message and exit
  --unsafe              Enable login tries on almost locked out accounts
  --force               Do not prompt for user confirmation
  --nocolor             Do not use color for output
  -v                    Verbosity level (-v or -vv)

credentials:
  -u USERNAME, --username USERNAME
                        Username
  -U USERFILE, --userfile USERFILE
                        File containing username list
  -p PASSWORD, --password PASSWORD
                        Password
  --lower               User as pass with lowercase password
  --upper               User as pass with uppercase password
  -t THRESHOLD, --threshold THRESHOLD
                        Number of password left allowed before locked out

ldap:
  -dc DOMAIN_CONTROLLER, --domain-controller DOMAIN_CONTROLLER
                        Domain controller
  -d DOMAIN, --domain DOMAIN
                        Domain FQDN
  -lP LDAP_PORT, --ldap-port LDAP_PORT
                        LDAP Port
  -lu LDAP_USER, --ldap-user LDAP_USER
                        LDAP User
  -lp LDAP_PASS, --ldap-pass LDAP_PASS
                        LDAP Password
  -lssl, --ldap-ssl     LDAP over TLS (ldaps)
  -lpage LDAP_PAGE_SIZE, --ldap-page-size LDAP_PAGE_SIZE
                        LDAP Paging size (Default: 200)

neo4j:
  -nh NEO4J_HOST, --neo4j-host NEO4J_HOST
                        Neo4J Host (Default: 127.0.0.1)
  -nP NEO4J_PORT, --neo4j-port NEO4J_PORT
                        Neo4J Port (Default: 7687)
  -nu NEO4J_USER, --neo4j-user NEO4J_USER
                        Neo4J user (Default: neo4j)
  -np NEO4J_PASS, --neo4j-pass NEO4J_PASS
                        Neo4J password (Default: neo4j)
```

### Unauthenticated

When used unauthenticated, **sprayhound** won't be able to check password policies. Account could be locked out.

```bash
# Single user, single password
sprayhound -u simba -p Pentest123.. -d hackn.lab -dc 10.10.10.1

# User list, single password
sprayhound -U ./users.txt -p Pentest123.. -d hackn.lab -dc 10.10.10.1

# User as pass
sprayhound -U ./users.txt -d hackn.lab -dc 10.10.10.1

# User as pass with password lowercase
sprayhound -U ./users.txt --lower -d hackn.lab -dc 10.10.10.1

# User as pass with password uppercase
sprayhound -U ./users.txt --upper -d hackn.lab -dc 10.10.10.1
```

### Authenticated

When providing a valid domain account, **sprayhound** will try and find default domain policy and check **badpwdcount** attribute of each user against lockout threshold. If too close, it will skip these accounts.

```bash
# Single user, single password
sprayhound -u simba -p Pentest123.. -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd

# All domain users, single password
sprayhound -p Pentest123.. -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd

# User as pass on all domain users
sprayhound -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd

# User as pass with password lowercase
sprayhound --lower -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd

# User as pass with password uppercase
sprayhound --upper -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd
```

Difference between **badpwdcount** and lockout threshold can be tuned using `--threshold` parameter. If set to **2**, and password policy locks out accounts after 5 login failure, then **sprayhound** won't test users with **badpwdcount** 3 (and more).

```bash
sprayhound -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd --threshold 1
```

## Bloodhound integration

When **sprayhound** finds accounts credentials, it can set these accounts as **Owned** in BloodHound. BloodHound information should be provided to this tool.

```bash
# -nh: Neo4J server
# -nP: Neo4J port
# -nu: Neo4J user
# -np: Neo4J password
sprayhound -d hackn.lab -dc 10.10.10.1 -lu pixis -lp P4ssw0rd -nh 127.0.0.1 -nP 7687 -nu neo4j -np bloodhound
```


## Changelog

```
v0.0.2
------
First release
```
