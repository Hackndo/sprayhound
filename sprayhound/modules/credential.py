# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from sprayhound.utils.utils import *


class Credential:
    def __init__(self, samaccountname, password=None, bad_password_count=0, threshold=0, dn=None):
        self.dn = dn
        self.samaccountname = samaccountname
        self.password = password
        self.bad_password_count = bad_password_count
        self.threshold = threshold

    def set_password(self, password):
        self.password = password

    def is_valid(self, ldap_connection, unsafe=False):
        if not unsafe:
            if self.threshold > 0 and self.threshold - self.bad_password_count <= 1:
                return RetCode(ERROR_THRESHOLD)
        return ldap_connection.test_credentials(self.samaccountname, self.password)