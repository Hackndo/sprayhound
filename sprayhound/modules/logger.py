# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import sys


class Logger:
    class Options:
        def __init__(self, verbosity=0):
            self.verbosity = verbosity

    def __init__(self, options=Options()):
        self._verbosity = options.verbosity

    def info(self, msg):
        if self._verbosity >= 1:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;34m[*]\033[0m {}".format(msg))

    def debug(self, msg):
        if self._verbosity >= 2:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;37m[*]\033[0m {}".format(msg))

    def warn(self, msg):
        if self._verbosity >= 0:
            msg = "\n    ".join(msg.split("\n"))
            print("\033[1;33m[!]\033[0m {}".format(msg))

    def error(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("\033[1;31m[X]\033[0m {}".format(msg), file=sys.stderr)

    def success(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("\033[1;32m[+]\033[0m {}".format(msg))

    def raw(self, msg):
        print("{}".format(msg), end='')

    def input(self, question, answers, default=False):
        if default and default not in answers:
            raise Exception("Default answer")

        answer = False
        while not answer or answer not in answers:
            answer = input("    {} [{}] ".format(question, "/".join(answer.upper() if answer == default else answer for answer in answers)))
            if not answer and default:
                answer = default
        return answer.lower()


    @staticmethod
    def highlight(msg):
        return "\033[1;33m{}\033[0m".format(msg)
