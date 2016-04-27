"""Get data from a local database instance of RouteViews.

This module serves as the interface between the WhoisAnalyzer object and
the database view of RouteViews data. The Route Views data must first be
pre-populated within a database. 

This module provides two classes:
    RVFetcher: provides a simple interface to fetch netblocks from the
               database
    RVComparator: Does some comparisons between a set of ASNs and
               network block data and the RouteViews DB. 

Attributes:
  verbose (boolean): Turns on verbosity of log messages.

"""
import sqlite3
from os.path import isfile
from collections import defaultdict
import ipaddress

global verbose
verbose = False

###############################################################

class RVFetcher:
    """Class to fetch objects from route views."""

    def __init__(self, dbfile):
        """RVFetcher constructor.

        Args:
            dbfile (file handle): handle to a sqlite3 database.
        """
        self.db = None
        if isfile(dbfile):
            self.db = sqlite3.connect(dbfile) 

    def __del__(self):
        """RVFetcher destructor.
        
        Close the database connection when we're done.
        """
        if self.db:
            self.db.close()

    def find_netblocks(self, start, end):
        """Find netblocks that fall between the given prefix bounds.

        Look up all netblocks that fall between the start and end
        bounds. IPv6 address blocks are ignored.

        Args:
            start(str): start prefix
            end(str): end prefix

        Returns:
            A cursor iterator that holds the results of the lookup.
        """
        stmt = "SELECT DISTINCT prefix,lastAS FROM routeadv WHERE (prefixStart >= ?) AND (prefixEnd <= ?)"
        args = []
        ipsobj = ipaddress.ip_address(start)
        ipeobj = ipaddress.ip_address(end)
        if isinstance(ipsobj, ipaddress.IPv6Address) or isinstance(ipeobj, ipaddress.IPv6Address):
            if verbose:
                print "Skipping IPv6 address block"
            return []
        args.append(int(ipsobj))
        args.append(int(ipeobj))
        cursor = self.db.cursor()
        if verbose:
            print "Executing sql statement:" + stmt + ":" + str(args)
        cursor.execute(stmt, args)
        return cursor.fetchall()


class RVComparator:
    """comparison between Whois objects and Route Views data."""

    def __init__(self, dbfile):
        """RVComparator constructor.

        Args:
            dbfile (file handle): handle to a sqlite3 database.
        """
        self.header = "SELECT DISTINCT lastAS,prefix,prefixStart,prefixEnd FROM routeadv WHERE "
        self.body = ""
        self.args = []
        self.orig_asnlist = []
        self.orig_pfxlist = []
        self.db = None
        if isfile(dbfile):
            self.db = sqlite3.connect(dbfile) 

    def __del__(self):
        """RVComparator destructor.
        
        Close the database connection when we're done.
        """
        if self.db:
            self.db.close()

    def add_asn(self, asn):
        """Add the ASN to the SQL query.

        Args:
            asn(str): The ASN handle

        Returns:
            True if the ASN was added.
        """
        if self.body != "":
            self.body += " OR "
        self.body += "(lastAS = ?)"
        self.args.append(asn)
        self.orig_asnlist.append(asn)
        return True

    def add_net(self, startAddr, endAddr, oaslist):
        """Add the network block to the SQL query.

        Note that IPv6 address blocks are ignored.

        Args:
            startAddr(str): The start address in the block.
            endAddr(str): The end address in the block.
            oaslist(list): a list of origin ASNs associated with this netblock.

        Returns:
            True if the network block was added.
        """
        ipsobj = ipaddress.ip_address(startAddr)
        ipeobj = ipaddress.ip_address(endAddr)
        if isinstance(ipsobj, ipaddress.IPv6Address) or isinstance(ipeobj, ipaddress.IPv6Address):
            return False
        if self.body != "":
            self.body += " OR "
        self.body += "((prefixStart >= ?) AND (prefixEnd <= ?))"
        sAddrInt = int(ipsobj)
        eAddrInt = int(ipeobj)
        self.args.append(sAddrInt)
        self.args.append(eAddrInt)
        self.orig_pfxlist.append({'start':sAddrInt, 'end':eAddrInt, 'oaslist': list(set(oaslist))})
        return True

    def is_pfx_known(self, start, end):
        """Check if the given network block is one that we know about.

        Args:
            start(str): network block start.
            end(str): network block end.

        Returns:
            True if the network block exists in our list; False if not.
        """
        for pfx in self.orig_pfxlist:
            if (start >= pfx['start']) and (end <= pfx['end']):
                return True
        return False

    def compare(self):
        """Compare known resources against Route Views data.

        Issue the sql query, check which prefixes and ASNs are unknown.

        Returns:
            An RVComparatorRes object that encapsulates the results of
            the comparison.
        """
        cmpres = RVComparatorRes()

        # First do a general sanity check
        #   check if ASN configured as originator is known
        for pfx in self.orig_pfxlist:
            for asn in pfx['oaslist']:
                if asn not in self.orig_asnlist: 
                    cmpres.add_unknown_oasn(asn, pfx)

        stmt = self.header + self.body
        res = defaultdict(dict)
        if self.db:
            cursor = self.db.cursor()
            if verbose:
                print "Executing sql statement:" + stmt + ":" + str(self.args)
            cursor.execute(stmt, self.args)
            all_rows = cursor.fetchall()
            for row in all_rows:
                asn = str(row[0])
                prefix = row[1]
                res[asn][prefix] = {'start': row[2], 'end': row[3]}

        # Check if prefix and ASN returned from RV are known
        for asn in res.keys():
            pfxlist = res[asn].keys()
            if asn not in self.orig_asnlist: 
                cmpres.add_unknown_asn(asn, pfxlist)

            for pfx in pfxlist:
                if not self.is_pfx_known(res[asn][pfx]['start'], res[asn][pfx]['end']):
                    cmpres.add_unknown_pfx(asn, pfx)

        return cmpres


    def compare_resources(self, resob):
        """Register known resources and compare against Route Views.

        Register all ASNs and Net objects from the WhoisAnalyzer object
        and then call compare() in order to check for differences
        against Route Views data.

        Args:
            resob(WhoisAnalyzer): object that holds the list of ASN and
                                  Net resources we are interested in
                                  analyzing.

        Returns:
            An RVComparatorRes object that encapsulates the results of
            the comparison.
        """
        if not resob:
            return None

        res = resob.get_resources()

        # Save each ASN that we find
        if 'asn' in res.keys():
            for (h, loc) in res['asn']:
                (fresh, data) = resob.get_data('asn', loc)
                if data and 'asn' in data.keys(): 
                    asn = data['asn']['startAsNumber']
                    if not self.add_asn(asn):
                        print "Could not process ASN " + str(asn)

        # Save each Net object that we find
        if 'net' in res.keys():
            for (h, loc) in res['net']:
                (fresh, data) = resob.get_data('net', loc)
                if data and 'net' in data.keys():
                    startAddr = data['net']['startAddress']
                    endAddr = data['net']['endAddress']
                    oaslist = []
                    if 'originASes' in data['net'].keys():
                        originAS = data['net']['originASes']
                        # Check if we have a dict
                        if isinstance(originAS, dict): 
                            # The dict element could contain a list
                            if isinstance(originAS['originAS'], list):
                                for oas in originAS['originAS']:
                                    asstr = oas.replace("AS","")
                                    oaslist.append(asstr)
                            else:
                                asstr = originAS['originAS'].replace("AS","")
                                oaslist.append(asstr)
                        else:
                            # we have a list
                            for oas in originAS: 
                                asstr = oas['originAS'].replace("AS","")
                                oaslist.append(asstr)
                    if not self.add_net(startAddr, endAddr, oaslist):
                        print "Could not process Net handle: " + h

        # Compare against route views
        return self.compare()


class RVComparatorRes:
    """Class for encapsulating the comparator result."""

    def __init__(self):
        self.unknown = defaultdict(dict)

    def add_unknown_oasn(self, asn, pfx):
        """Register an unknown originating AS.

        Register the ASN originating a known prefix but was not
        configured as the originating AS in whois.

        Args:
            asn: The (known) ASN originating the prefix.
            pfx: The prefix from a known block that was originated.

        Returns:
            None.
        """
        ah = "AS" + str(asn)
        if ah in self.unknown['oasn'].keys():
            self.unknown['oasn'][ah].append(pfx)
        else:
            self.unknown['oasn'][ah] = [pfx]

    def get_unknown_oasn(self):
        """Return the list of unknown originating ASNs.

        Returns:
            A dict structure that maps ASNs to the prefix values.
        """
        if 'oasn' in self.unknown.keys():
            return self.unknown['oasn']
        return {}

    def add_unknown_asn(self, asn, pfxlist):
        """Register an unknown AS.

        Register the previously unknown ASN that was found to originate
        a known prefix. 

        Args:
            asn: The (unknown) ASN originating the prefix.
            pfx: The prefix from a known block that was originated.

        Returns:
            None.
        """
        ah = "AS" + str(asn)
        if ah in self.unknown['asn'].keys():
            self.unknown['asn'][ah].extend(pfxlist)
        else:
            self.unknown['asn'][ah] = pfxlist

    def get_unknown_asn(self):
        """Return the list of unknown ASNs.

        Returns:
            A dict structure that maps ASNs to the prefix values.
        """
        if 'asn' in self.unknown.keys():
            return self.unknown['asn']
        return {}

    def add_unknown_pfx(self, asn, pfx):
        """Register an unknown prefix.

        Register the previously unknown prefix that was originated from
        a known ASN.

        Args:
            asn: The known ASN originating the prefix.
            pfx: The unknown prefix that was originated.

        Returns:
            None.
        """
        ah = "AS" + str(asn)
        if pfx in self.unknown['pfx'].keys():
            self.unknown['pfx'][pfx].append(ah)
        else:
            self.unknown['pfx'][pfx] = [ah]

    def get_unknown_pfx(self):
        """Return the list of unknown prefixes.

        Returns:
            A dict structure that maps prefixes to the ASNs they were
            originated from.
        """
        if 'pfx' in self.unknown.keys():
            return self.unknown['pfx']
        return {}


    # Process all unknown dependencies that were detected in Routeviews
    def process_unknown_resources(self, analyzer):
        """Process all unknown dependencies.

        Feed all unknown dependencies that were detected in
        Routeviews through the WhoisAnalyzer object.

        Args:
            analyzer(WhoisAnalyzer): the analyzer object

        Returns:
            None.
        """
        if not analyzer:
            return
        objs = self.get_unknown_asn()
        for o_h in objs.keys():
            comment = "Unknown " + o_h + " originating " + ', '.join(map(str, objs[o_h]))
            # XXX Dont Process new collections automatically
            # analyzer.process_new_collection('asn', o_h, comment)
            analyzer.append_message(comment)
        objs = self.get_unknown_pfx()
        for o_h in objs.keys():
            comment = "Unknown prefix " + o_h + " originated from " + ', '.join(map(str, objs[o_h]))
            # XXX Dont Process new collections automatically
            # analyzer.process_new_collection('cidr', o_h, comment)
            analyzer.append_message(comment)
        objs = self.get_unknown_oasn()
        for o_h in objs.keys():
            comment = "Origination for " + ', '.join(map(str, objs[o_h])) + " from " + o_h + " is inconsistent with whois"
            analyzer.append_message(comment)

