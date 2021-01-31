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
    group_credentials.add_argument('-P', '--passwordfile', action='store', help="File containing password list")
    
    group_tests = parser.add_argument_group('tests')
    group_tests.add_argument('-t', '--threshold', action='store', type=int, default=1, help="Number of password left allowed before locked out")
    group_tests.add_argument('-l', '--loop-time', action='store', type=int, default=10, help="Interval between password spray sessions in seconds (Default: 10)")


    group_ldap = parser.add_argument_group('ldap')
    group_ldap.add_argument('-dc', '--domain-controller', action='store', help='Domain controller')
    group_ldap.add_argument('-d', '--domain', action='store', help='Domain FQDN')
    group_ldap.add_argument('-lP', '--ldap-port', default='389', action='store', help='LDAP Port')
    group_ldap.add_argument('-lu', '--ldap-user', action='store', help='LDAP User')
    group_ldap.add_argument('-lp', '--ldap-pass', action='store', help='LDAP Password')
    group_ldap.add_argument('-lssl', '--ldap-ssl', action='store_true', help='LDAP over TLS (ldaps)')
    group_ldap.add_argument('-lpage', '--ldap-page-size', type=int, default=200, help='LDAP Paging size (Default: 200)')

    group_neo4j = parser.add_argument_group('neo4j')
    group_neo4j.add_argument('-nh', '--neo4j-host', default='127.0.0.1', action='store', help='Neo4J Host (Default: 127.0.0.1)')
    group_neo4j.add_argument('-nP', '--neo4j-port', default='7687', action='store', help='Neo4J Port (Default: 7687)')
    group_neo4j.add_argument('-nu', '--neo4j-user', default='neo4j', action='store', help='Neo4J user (Default: neo4j)')
    group_neo4j.add_argument('-np', '--neo4j-pass', default='neo4j', action='store', help='Neo4J password (Default: neo4j)')

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
