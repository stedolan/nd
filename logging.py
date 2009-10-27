import sys

[LOG_ERR, LOG_WARN, LOG_INFO, LOG_DEBUG] = range(4)

_logfile = sys.stdout


fmts = {
    LOG_ERR: chr(27) + "[31mError: %s" + chr(27) + "[0m\n",
    LOG_WARN: chr(27) + "[33mWarning: %s" + chr(27) + "[0m\n",
    LOG_INFO: "%s\n",
    LOG_DEBUG: ""  #"%s\n",
}


def log(level, msg):
    if "%s" in fmts[level]:
        _logfile.write(fmts[level] % msg)

def lerr(msg):
    log(LOG_ERR, msg)
def lwarn(msg):
    log(LOG_WARN, msg)
def linfo(msg):
    log(LOG_INFO, msg)
def ldebug(msg):
    log(LOG_DEBUG, msg)
