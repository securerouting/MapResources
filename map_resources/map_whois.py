#!/usr/bin/python

""" map_whois.py - Map whois resources

This script enables one to discover network resources in ARIN's whois
database that are could belong to an organization. A starting point in
the form of a known POC handle, organization handle, net handle or asn
number is assumed; the tool thereafter queries ARIN's RESTful API in
order to detect other resources that the organization may hold.

"""

import sys

from map_resources.analyze import AnalyzeOptExtension, WhoisOptParser, WhoisAnalyzer
from map_resources.whois_rv_cmp import RVComparator, RVFetcher

ap = AnalyzeOptExtension(WhoisOptParser("map_whois"))
__doc__ += ap.get_help()

def main(argv):

    opts = ap.parse(argv)
    c = WhoisAnalyzer(opts['store'], opts['threshold'],
            opts['whitelist'], opts['blacklist'])
    try:
        resob = c.analyze(opts['objlist'])
    except Exception as e:
        print e
        sys.exit(2)

    rvc = None
    rvf = None

    # Try comparing against whois
    if resob and opts['rvdb']:
        rvc = RVComparator(opts['rvdb'])
        rvf = RVFetcher(opts['rvdb'])
        if rvc:
            rvcres = rvc.compare_resources(resob)
            if rvcres:
                rvcres.process_unknown_resources(c)

    c.generate_results(opts, rvf)


if __name__ == "__main__":
    main(sys.argv[1:])


