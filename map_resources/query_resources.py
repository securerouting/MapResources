#!/usr/bin/python

""" query_resource.py - Query whois resources

This script enables one to query the ARIN whois database for data
corresponding to given object handles.

"""

from map_resources.analyze import WhoisOptParser, WhoisObjectFormatter

from collections import defaultdict
from pprint import pprint
import argparse
import sys
from bson import json_util

ap = WhoisOptParser("query_resources")
__doc__ += ap.get_help()


def main(argv):

    opts = ap.parse(argv)
    store = opts['store']
    objlist = opts['objlist']
    jsonfile = opts['jsonfile']

    resources = defaultdict(list)
    f = WhoisObjectFormatter(store)

    # Get the various resource types and URIs 
    for k in objlist.keys():
        typepfx = objlist[k]
        (r_handle, idstrlist) = store.get_idstr(typepfx, k)
        for (ctype, loc) in idstrlist:
            obj = {}
            # Check if we need to fetch extended info
            if opts['extended']:
                if ctype == 'net':
                    obj = f.get_netinfo(loc)
                elif ctype == 'org':
                    obj = f.get_orginfo(loc)
                elif ctype == 'poc':
                    obj = f.get_pocinfo(loc)
                elif ctype == 'asn':
                    obj = f.get_asninfo(loc)
                else:
                    obj = h
            else:
                obj = store.fetch(ctype, loc)
            res_json = json_util.dumps(obj)
            outstr = k + "|" + res_json + "\n"
            if opts['verbose']:
                print outstr
            if jsonfile:
                jsonfile.write(outstr)

if __name__ == "__main__":
    main(sys.argv[1:])

