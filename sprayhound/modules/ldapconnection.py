# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import socket
import ldap
from ldap.controls import SimplePagedResultsControl

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
        self._get_conn()
        if not self.username or not self.password or not self.domain:
            return ERROR_LDAP_NO_CREDENTIALS
        try:
            self.log.debug("Trying bind with {}@{} : {}".format(self.username, self.domain, self.password))
            self._conn.simple_bind_s('{}@{}'.format(self.username, self.domain), self.password)
            self.log.debug("LDAP authentication successful!")
            return ERROR_SUCCESS
        except ldap.SERVER_DOWN:
            self.log.error("Service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
            raise
        except ldap.INVALID_CREDENTIALS:
            self.log.error("Invalid credentials {}/{}:{}".format(self.domain, self.username, self.password))
            raise

    def test_credentials(self, username, password):
        self.username = username
        self.password = password

        self._get_conn()
        try:
            self._conn.simple_bind_s('{}@{}'.format(self.username, self.domain), self.password)
            return ERROR_SUCCESS
        except ldap.SERVER_DOWN:
            self.log.error("Service unavailable on {}://{}:{}".format(self.scheme, self.host, self.port))
            raise
        except ldap.INVALID_CREDENTIALS:
            return ERROR_LDAP_CREDENTIALS
        except Exception as e:
            self.log.error("Unexpected error while trying {}:{}".format(username, password))
            raise

    def get_users(self, dispatcher, user=None, disabled=True):
        filters = ["(objectClass=User)"]
        if user:
            filters.append("(samAccountName={})"+format(user.lower()))
        if not disabled:
            filters.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")

        if len(filters) > 1:
            filters = '(&' + ''.join(filters) + ')'
        else:
            filters = filters[0]
        try:
            self.log.debug("Looking in {}".format(self.domain_dn))
            ldap_attributes = ['samAccountName', 'badPwdCount']
            self.log.debug("Users will be retrieved using paging")
            res = self.get_paged_users(filters, ldap_attributes)

            results = [
                Credential(
                    samaccountname=entry['sAMAccountName'][0].decode('utf-8'),
                    bad_password_count=int(entry['badPwdCount'][0]),
                    threshold=self.domain_threshold if dn not in self.granular_threshold else self.granular_threshold[dn]
                ) for dn, entry in res
                if isinstance(entry, dict)
                   and entry['sAMAccountName'][0].decode('utf-8')[-1] != '$'
            ]

            dispatcher.credentials = results
            return ERROR_SUCCESS
        except Exception as e:
            self.log.error("An error occurred while looking for users via LDAP")
            raise

    def get_paged_users(self, filters, attributes):
        pages = 0
        result = []

        page_control = SimplePagedResultsControl(True, size=self.page_size, cookie='')
        res = self._conn.search_ext(
            self.domain_dn,
            ldap.SCOPE_SUBTREE,
            filters,
            attributes,
            serverctrls=[page_control]
        )

        while True:
            pages += 1
            self.log.debug("Page {} done".format(pages))
            rtype, rdata, rmsgid, serverctrls = self._conn.result3(res)
            result.extend(rdata)
            controls = [ctrl for ctrl in serverctrls if ctrl.controlType == SimplePagedResultsControl.controlType]
            if not controls:
                self.log.error('The server ignores RFC 2696 control')
                break
            if not controls[0].cookie:
                break
            page_control.cookie = controls[0].cookie
            res = self._conn.search_ext(
                self.domain_dn,
                ldap.SCOPE_SUBTREE,
                filters,
                attributes,
                serverctrls=[page_control]
            )
        return result

    def get_password_policy(self):
        default_policy_container = self.domain_dn
        granular_policy_container = 'CN=Password Settings Container,CN=System,{}'.format(self.domain_dn)
        granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
        granular_policy_attribs = ['msDS-LockoutThreshold', 'msDS-PSOAppliesTo']
        try:
            # Load domain-wide policy.
            results = self._conn.search_s(default_policy_container, ldap.SCOPE_BASE)
        except ldap.LDAPError as e:
            self.log.error("An LDAP error occurred while getting password policy")
            raise
        self.domain_threshold = int(results[0][1]['lockoutThreshold'][0])

        results = self._conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter, granular_policy_attribs)
        for policy in results:
            if len(policy[1]['msDS-PSOAppliesTo']) > 0:
                for dest in policy[1]['msDS-PSOAppliesTo']:
                    self.granular_threshold[dest.decode('utf-8')] = int(policy[1]['msDS-LockoutThreshold'][0])

        return ERROR_SUCCESS

    def _get_conn(self):
        if self._conn is not None:
            return ERROR_SUCCESS
        self._conn = ldap.initialize('{}://{}:{}'.format(self.scheme, self.host, self.port))
        self._conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 3.0)
        self._conn.protocol_version = 3
        self._conn.set_option(ldap.OPT_REFERRALS, 0)
        return ERROR_SUCCESS

