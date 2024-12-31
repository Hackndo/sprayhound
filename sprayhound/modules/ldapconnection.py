# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import socket
import ldap3

from sprayhound.modules.credential import Credential
from sprayhound.utils.defines import *


class LdapConnection:
    class Options:
        def __init__(self, host, domain, username, password, port=None, ssl=False, page_size=200):
            self.host = host
            self.domain = domain
            self.username = username
            self.password = password
            self.ssl = ssl
            self.scheme = "ldaps" if self.ssl else "ldap"
            self.page_size = page_size
            if port is None:
                self.port = 636 if self.ssl else 389
            else:
                self.port = port

    def __init__(self, options, log):
        self.host = options.host
        self.domain = options.domain
        self.username = options.username
        self.password = options.password
        self.ssl = options.ssl
        self.scheme = options.scheme
        self.port = options.port
        self.page_size = options.page_size
        self.log = log
        self.domain_dn = None
        self._conn = None
        self.server = None
        self.domain_threshold = 0
        self.granular_threshold = {}  # keys are policy DNs
        self.get_domain_dn()

    def get_domain(self):
        host_fqdn = socket.getfqdn()
        if "." not in host_fqdn:
            return ERROR_LDAP_NOT_FQDN_DOMAIN
        self.domain = host_fqdn.split('.', 1)[1]

    def get_domain_dn(self):
        if not self.domain:
            try:
                self.get_domain()
            except Exception as e:
                self.log.error("Could not get domain name")
                raise
        if '.' not in self.domain:
            return ERROR_LDAP_NOT_FQDN_DOMAIN
        self.domain_dn = ','.join(['DC=' + part for part in self.domain.split('.')])

    def login(self):
        self._get_server()
        if not self.username or not self.password or not self.domain:
            return ERROR_LDAP_NO_CREDENTIALS

        if(self.username.find("\\") == -1):
            self.username = self.domain + "\\" + self.username

        try:
            self.log.debug("Trying bind with {} : {}".format(self.username, self.password))
            self._conn = ldap3.Connection(self.server, authentication=ldap3.NTLM, user=self.username, password=self.password, auto_referrals=False, raise_exceptions=True)
            self._conn.bind()
            self.log.debug("LDAP authentication successful!")
            return ERROR_SUCCESS
        except ldap3.core.exceptions.LDAPSocketOpenError:
            self.log.error("Service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
            raise
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            self.log.error("Invalid credentials {}/{}:{}".format(self.domain, self.username, self.password))
            print([self.username])
            raise


    def test_credentials(self, username, password):
        self.username = username
        self.password = password

        self._get_server()

        try:
            self._conn = ldap3.Connection(self.server, authentication=ldap3.NTLM, user=self.domain + "\\" + self.username, password=self.password, auto_referrals=False, raise_exceptions=True)
            self._conn.bind()
            return ERROR_SUCCESS
        except ldap3.core.exceptions.LDAPSocketOpenError:
            self.log.error("Service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
            raise
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            return ERROR_LDAP_CREDENTIALS
        except Exception as e:
            self.log.error("Unexpected error while trying {}:{}".format(self.domain + "\\" + self.username, password))
            raise

    def get_users(self, dispatcher, users=None, disabled=True):
        filters = ["(objectClass=User)"]
        if users:
            if len(users) == 1:
                filters.append("(samAccountName={})".format(users[0].lower()))
            else:
                filters.append("(|")
                filters.append("".join("(samAccountName={})".format(user.lower()) for user in users))
                filters.append(")")
        if not disabled:
            filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")

        if len(filters) > 1:
            filters = '(&' + ''.join(filters) + ')'
        else:
            filters = filters[0]
        try:
            self.log.debug("Looking in {}".format(self.domain_dn))
            ldap_attributes = ['samAccountName', 'badPwdCount', 'msDS-ResultantPSO']
            self.log.debug("Users will be retrieved using paging")
            res = self.get_paged_users(filters, ldap_attributes)

            results = [
                Credential(
                    samaccountname=entry['attributes']['sAMAccountName'],
                    bad_password_count=0 if 'badPwdCount' not in entry['attributes'] else int(entry['attributes']['badPwdCount']),
                    threshold=self.domain_threshold if entry['dn'] not in self.granular_threshold else self.granular_threshold[entry['dn']],
                    pso=True if 'msDS-ResultantPSO' in entry['attributes'] and isinstance(entry['attributes']['msDS-ResultantPSO'], str) and entry['attributes']['msDS-ResultantPSO'].upper().startswith('CN=') else False
                ) for entry in res if isinstance(entry, dict) and 'attributes' in entry and entry['attributes']['sAMAccountName'][-1] != '$'
            ]

            dispatcher.credentials = results
            return ERROR_SUCCESS
        except Exception as e:
            self.log.error("An error occurred while looking for users via LDAP")
            raise

    def get_paged_users(self, filters, attributes):
        result = []

        entry_generator = self._conn.extend.standard.paged_search(search_base = self.domain_dn,
                                                 search_filter = filters,
                                                 search_scope = ldap3.SUBTREE,
                                                 attributes = attributes,
                                                 paged_size = 5,
                                                 generator=True)

        total_entries=0
        for entry in entry_generator:
            total_entries += 1
            result.append(entry)

        return result

    def get_password_policy(self):
        default_policy_container = self.domain_dn
        granular_policy_container = 'CN=Password Settings Container,CN=System,{}'.format(self.domain_dn)
        granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
        granular_policy_attribs = ['msDS-LockoutThreshold', 'msDS-PSOAppliesTo']
        try:
            # Load domain-wide policy.
            self._conn.search(default_policy_container, '(objectClass=*)', search_scope=ldap3.BASE, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES])
        except ldap3.core.exceptions.LDAPException as e:
            self.log.error("An LDAP error occurred while getting password policy")
            raise
        self.domain_threshold = int(self._conn.response[0]['attributes']['lockoutThreshold'])

        #TODO: implement granular policy retrieval
        #results = self._conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter, granular_policy_attribs)
        #print(results)
        #for policy in results:
        #    if len(policy[1]['msDS-PSOAppliesTo']) > 0:
        #        for dest in policy[1]['msDS-PSOAppliesTo']:
        #            self.granular_threshold[dest.decode('utf-8')] = int(policy[1]['msDS-LockoutThreshold'][0])

        return ERROR_SUCCESS

    def _get_server(self):
        self.server = ldap3.Server('{}://{}:{}'.format(self.scheme, self.host, self.port))

        return ERROR_SUCCESS

