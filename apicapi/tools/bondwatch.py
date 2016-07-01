#!/usr/bin/env python
#
# Watches bond link and if the master changes, it reasserts all endponts
#

import fnmatch
import logging
import os
import os.path
import sys
import time


# Default config. First 2 params can be set by command-line args
config = {
    'bond-name': 'bond0',
    'retry-interval': 1,
    'valid-uuid': 0,
    'proc-bond-path': '/proc/net/bonding',
    'proc-bond-key': 'Currently Active Slave:',
    'opflex-ep-dir': '/var/lib/opflex-agent-ovs/endpoints',
}
logging.basicConfig(
    format='%(asctime)s %(message)s',
    datefmt='%Y.%m.%d %H.%M.%S:')


def err(msg):
    e = sys.exc_info()[1]
    if e is not None:
        logging.error(':'.join([msg, e.message]))
    else:
        logging.error(msg)


def update_config():
    """
    usage (arguments are optional):
    bond-watch <bond-name> <retry-interval>
    """
    args = sys.argv[1:]
    if len(args) > 0:
        config['bond-name'] = args[0]
    if len(args) > 1:
        config['retry-interval'] = args[1]
    return config


def is_valid_uuid():
    try:
        if os.getuid() == config['valid-uuid']:
            return True
    except:
        err('Error in getuid')
    return False


def check_master(currmaster):
    # returns: updated, current-master
    newmaster = None
    fname = os.path.join(config['proc-bond-path'], config['bond-name'])
    with open(fname, 'r') as fd:
        for line in fd:
            if config['proc-bond-key'] in line:
                newmaster = line.split(':')[-1]
    if currmaster != newmaster:
        return (True, newmaster)
    return (False, currmaster)


def reassert_eps():
    # returns False if it is not able to re-assert endpoints
    try:
        files = os.listdir(config['opflex-ep-dir'])
        for filename in fnmatch.filter(files, '*.ep'):
            ffilename = os.path.join(config['opflex-ep-dir'], filename)
            if os.path.isfile(ffilename):
                os.utime(ffilename, None)
    except:
        err('In reasserting EPs')
        return False
    return True


def main():
    update_config()
    if not is_valid_uuid():
        err('Not a valid user. Exiting')
        return

    currmaster = None
    while True:
        try:
            updated, newmaster = check_master(currmaster)
            if updated:
                reasserted = reassert_eps()
                if reasserted:
                    currmaster = newmaster
                else:
                    err('In reasserting EPs (will retry)')
        except:
            err('Error in checking for master (will retry)')
        time.sleep(config['retry-interval'])


if __name__ == "__main__":
    main()
