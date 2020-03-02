# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import sys


class Logger:
    DEFAULT  = "\033[0m"

    RED      = "\033[1;31m"
    GREEN    = "\033[1;32m"
    YELLOW   = "\033[1;33m"
    BLUE     = "\033[1;34m"
    WHITE    = "\033[1;37m"



    class Options:
        def __init__(self, verbosity=0):
            self.verbosity = verbosity

    def __init__(self, options=Options()):
        self._verbosity = options.verbosity

    def info(self, msg):
        if self._verbosity >= 1:
            msg = "\n    ".join(msg.split("\n"))
            print("{}[*]{} {}".format(Logger.BLUE, Logger.DEFAULT, msg))

    def debug(self, msg):
        if self._verbosity >= 2:
            msg = "\n    ".join(msg.split("\n"))
            print("{}[*]{} {}".format(Logger.WHITE, Logger.DEFAULT, msg))

    def warn(self, msg):
        if self._verbosity >= 0:
            msg = "\n    ".join(msg.split("\n"))
            print("{}[!]{} {}".format(Logger.YELLOW, Logger.DEFAULT, msg))

    def error(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("{}[X]{} {}".format(Logger.RED, Logger.DEFAULT, msg), file=sys.stderr)

    def success(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("{}[+]{} {}".format(Logger.GREEN, Logger.DEFAULT, msg))

    def raw(self, msg):
        print("{}".format(msg), end='')

    def input(self, question, answers, default=False):
        if default and default not in answers:
            raise Exception("Default answer not valid")

        answer = False
        while not answer or answer not in answers:
            answer = input("    {} [{}] ".format(question, "/".join(answer.upper() if answer == default else answer for answer in answers)))
            if not answer and default:
                answer = default
        return answer.lower()

    @staticmethod
    def highlight(msg):
        return "{}{}{}".format(Logger.YELLOW, msg, Logger.DEFAULT)

    @staticmethod
    def colorize(msg, color):
        return "{}{}{}".format(color, msg, Logger.DEFAULT)

