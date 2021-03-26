# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import sys


class Logger:
        



    class Options:
        def __init__(self, verbosity=0, nocolor=False):
            self.verbosity = verbosity
            self.nocolor = nocolor

    def __init__(self, options=Options()):
        if options.nocolor:
            self.DEFAULT  = ""

            self.RED      = ""
            self.GREEN    = ""
            self.YELLOW   = ""
            self.BLUE     = ""
            self.WHITE    = ""
        else:
            self.DEFAULT  = "\033[0m"

            self.RED      = "\033[1;31m"
            self.GREEN    = "\033[1;32m"
            self.YELLOW   = "\033[1;33m"
            self.BLUE     = "\033[1;34m"
            self.WHITE    = "\033[1;37m"
        self._verbosity = options.verbosity

    def info(self, msg):
        if self._verbosity >= 1:
            msg = "\n    ".join(msg.split("\n"))
            print("{}[*]{} {}".format(self.BLUE, self.DEFAULT, msg))

    def debug(self, msg):
        if self._verbosity >= 2:
            msg = "\n    ".join(msg.split("\n"))
            print("{}[*]{} {}".format(self.WHITE, self.DEFAULT, msg))

    def warn(self, msg):
        if self._verbosity >= 0:
            msg = "\n    ".join(msg.split("\n"))
            print("{}[!]{} {}".format(self.YELLOW, self.DEFAULT, msg))

    def error(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("{}[X]{} {}".format(self.RED, self.DEFAULT, msg), file=sys.stderr)

    def success(self, msg):
        msg = "\n    ".join(msg.split("\n"))
        print("{}[+]{} {}".format(self.GREEN, self.DEFAULT, msg))

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

    def highlight(self, msg):
        return "{}{}{}".format(self.YELLOW, msg, self.DEFAULT)

    def colorize(self, msg, color):
        return "{}{}{}".format(color, msg, self.DEFAULT)

