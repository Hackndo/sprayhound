# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import sys
import argparse
import pkg_resources

from sprayhound.utils.defines import *

version = pkg_resources.require("sprayhound")[0].version


def get_args():
    examples = '''example:
    sprayhound -d adsec.local -p Winter202
    sprayhound -U userlist.txt -d adsec.local
    '''

    parser = argparse.ArgumentParser(
        prog="sprayhound",
        description='sprayhound v{} - Password spraying'.format(version),
        epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter
    )

    group_credentials = parser.add_argument_group('credentials')
    group_credentials.add_argument('-u', '--username', action='store', help="Username")
    group_credentials.add_argument('-U', '--userfile', action='store', help="File containing username list")
    group_credentials.add_argument('-p', '--password', action='store', help="Password")

    group_ldap = parser.add_argument_group('ldap')
    group_ldap.add_argument('-dc', '--domain-controller', dest='domaincontroller', action='store', help='Domain controller')
    group_ldap.add_argument('-d', '--domain', action='store', help='Domain FQDN')
    group_ldap.add_argument('-lP', '--ldap-port', dest='ldapport', default='389', action='store', help='LDAP Port')
    group_ldap.add_argument('-lu', '--ldap-user', dest='ldapuser', action='store', help='LDAP User')
    group_ldap.add_argument('-lp', '--ldap-pass', dest='ldappass', action='store', help='LDAP Password')
    group_ldap.add_argument('-lssl', '--ldap-ssl', dest='ldapssl', action='store_true', help='LDAP over TLS (ldaps)')
    group_ldap.add_argument('-lpage', '--ldap-page-size', type=int, dest='ldappagesize', default=200, help='LDAP Paging size (Default: 200)')

    group_neo4j = parser.add_argument_group('neo4j')
    group_neo4j.add_argument('-nh', '--neo4j-host', dest='neo4jhost', default='127.0.0.1', action='store', help='Neo4J Host (Default: 127.0.0.1)')
    group_neo4j.add_argument('-nP', '--neo4j-port', dest='neo4jport', default='7687', action='store', help='Neo4J Port (Default: 7687)')
    group_neo4j.add_argument('-nu', '--neo4j-user', dest='neo4juser', default='neo4j', action='store', help='Neo4J user (Default: neo4j)')
    group_neo4j.add_argument('-np', '--neo4j-pass', dest='neo4jpass', default='neo4j', action='store', help='Neo4J password (Default: neo4j)')

    parser.add_argument('--unsafe', action='store_true', help='Enable login tries on almost locked out accounts')

    parser.add_argument('-v', action='count', default=0, help='Verbosity level (-v or -vv)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(RetCode(ERROR_MISSING_ARGUMENTS).error_code)

    return parser.parse_args()


def sprayhound_exit(logger, error):
    logger.error(error[1])
    sys.exit(error[0])


def sprayhound_error(logger, error):
    logger.error(error[1])
