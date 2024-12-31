# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from sprayhound.utils.utils import *


class Credential:
    def __init__(self, samaccountname, password=None, bad_password_count=0, threshold=0, dn=None, pso=False):
        self.dn = dn
        self.samaccountname = samaccountname
        self.password = password
        self.bad_password_count = bad_password_count
        self.threshold = threshold
        self.pso = pso

    def set_password(self, password):
        self.password = password

    def is_tested(self, threshold=1, unsafe=False):
        to_be_tested = True
        if not unsafe:
            if self.pso or (self.threshold > 0 and self.threshold - self.bad_password_count <= threshold):
                to_be_tested = False
        return to_be_tested, self.bad_password_count

    def is_valid(self, ldap_connection, threshold=1, unsafe=False):
        if not unsafe:
            if self.pso:
                return ERROR_PSO
            if self.threshold > 0 and self.threshold - self.bad_password_count <= threshold:
                return ERROR_THRESHOLD
        return ldap_connection.test_credentials(self.samaccountname, self.password)