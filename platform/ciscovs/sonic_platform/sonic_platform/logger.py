# -*- coding: utf-8 -*-
########################################################################
# vSONiC
#
# class for Logging used by sonic_platform
#
########################################################################

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

LOG_DIR = "/var/log/vsonic/"
LOG_FILE = LOG_DIR + "sonic_platform.log"

debuglevel = 0

def Singleton(cls):
    _instance = {}

    def _singleton(*args, **kargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kargs)
        return _instance[cls]

    return _singleton

@Singleton
class sonic_platform_logger(object):
    def __init__(self):
        if not os.path.exists(LOG_DIR):
            os.system("sudo mkdir -p %s" % LOG_DIR)
            os.system("sudo chmod a+rx %s" % LOG_DIR)
            os.system("sudo touch %s" % LOG_FILE)
            os.system("sudo chmod a+rw %s" % LOG_FILE)
            os.system("sync")
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.handler = RotatingFileHandler(filename = LOG_FILE, maxBytes = 1 * 1024 * 1024, backupCount = 1)
        self.handler.setFormatter(logging.Formatter('%(asctime)s, %(filename)s, %(levelname)s, %(message)s'))
        self.handler.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)

    def log_error(self, s):
        self.logger.error("LINE:%s, %s" % (sys._getframe(1).f_lineno, s))

    def log_info(self, s):
        self.logger.info("LINE:%s, %s" % (sys._getframe(1).f_lineno, s))

    def log_debug(self, s):
        self.logger.debug("LINE:%s, %s" % (sys._getframe(1).f_lineno, s))
