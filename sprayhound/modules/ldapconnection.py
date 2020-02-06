# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import socket
import ldap

from sprayhound.modules.credential import Credential
from sprayhound.utils.defines import *


class LdapConnection:
    class Options:
        def __init__(self, host, domain, username, password, port=None, ssl=False):
            self.host = host
            self.domain = domain
            self.username = username
            self.password = password
            self.ssl = ssl
            self.scheme = "ldaps" if self.ssl else "ldap"
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
        self.log = log
        self.domain_dn = None
        self._conn = None
        self.domain_threshold = 0
        self.granular_threshold = {}  # keys are policy DNs
        self.get_domain_dn()

    def get_domain(self):
        host_fqdn = socket.getfqdn()
        if "." not in host_fqdn:
            return RetCode(ERROR_LDAP_NOT_FQDN_DOMAIN)
        self.domain = host_fqdn.split('.', 1)[1]

    def get_domain_dn(self):
        if not self.domain:
            ret = self.get_domain()
            if not ret.success():
                return ret
        if '.' not in self.domain:
            return RetCode(ERROR_LDAP_NOT_FQDN_DOMAIN)
        self.domain_dn = ','.join(['DC=' + part for part in self.domain.split('.')])

    def login(self):
        self._get_conn()
        if not self.username or not self.password or not self.domain:
            return RetCode(ERROR_LDAP_NO_CREDENTIALS)
        try:
            self.log.debug("Trying bind with {}@{} : {}".format(self.username, self.domain, self.password))
            self._conn.simple_bind_s('{}@{}'.format(self.username, self.domain), self.password)
            self.log.debug("LDAP authentication successful!")
            return RetCode(ERROR_SUCCESS)
        except ldap.SERVER_DOWN:
            return RetCode(ERROR_LDAP_SERVICE_UNAVAILABLE, "Service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
        except ldap.INVALID_CREDENTIALS:
            return RetCode(ERROR_LDAP_CREDENTIALS, "Invalid credentials {}/{}:{}".format(self.domain, self.username, self.password))

    def test_credentials(self, username, password):
        self.username = username
        self.password = password
        return self.login()

    def get_users(self, dispatcher, user=None, disabled=True):
        filters = ["(objectClass=User)"]
        if user:
            filters.append("(samAccountName={})"+format(user.lower()))
        if not disabled:
            filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")

        if len(filters) > 1:
            filter = '(&' + ''.join(filters) + ')'
        else:
            filter = filters[0]
        try:
            self.log.debug("Looking in {}".format(self.domain_dn))
            ldap_attributes = ['samAccountName', 'badPwdCount']
            res = self._conn.search_s(self.domain_dn, ldap.SCOPE_SUBTREE, filter, ldap_attributes)

            results = [
                Credential(
                    samaccountname=entry['sAMAccountName'][0].decode('utf-8'),
                    bad_password_count=int(entry['badPwdCount'][0]),
                    threshold=self.domain_threshold if dn not in self.granular_threshold else self.granular_threshold[dn]
                ) for dn, entry in res if isinstance(entry, dict) and entry['sAMAccountName'][0].decode('utf-8')[-1] != '$'
            ]

            dispatcher.credentials = results
            return RetCode(ERROR_SUCCESS)
        except Exception as e:
            return RetCode(ERROR_UNDEFINED, e)

    def get_password_policy(self):
        default_policy_container = self.domain_dn
        granular_policy_container = 'CN=Password Settings Container,CN=System,{}'.format(self.domain_dn)
        granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
        granular_policy_attribs = ['msDS-LockoutThreshold', 'msDS-PSOAppliesTo']
        try:
            # Load domain-wide policy.
            results = self._conn.search_s(default_policy_container, ldap.SCOPE_BASE)
        except ldap.LDAPError as e:
            return RetCode(ERROR_UNDEFINED, e)
        self.domain_threshold = int(results[0][1]['lockoutThreshold'][0])

        results = self._conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter, granular_policy_attribs)
        for policy in results:
            if len(policy[1]['msDS-PSOAppliesTo']) > 0:
                for dest in policy[1]['msDS-PSOAppliesTo']:
                    self.granular_threshold[dest.decode('utf-8')] = int(policy[1]['msDS-LockoutThreshold'][0])

        return RetCode(ERROR_SUCCESS)

    def _get_conn(self):
        if self._conn is not None:
            return RetCode(ERROR_SUCCESS)
        self._conn = ldap.initialize('{}://{}:{}'.format(self.scheme, self.host, self.port))
        self._conn.protocol_version = 3
        self._conn.set_option(ldap.OPT_REFERRALS, 0)
        return RetCode(ERROR_SUCCESS)

