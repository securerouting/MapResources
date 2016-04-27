import sys
import os
from StringIO import StringIO
import unittest
import map_resources.fetch_whois as fetch_whois
import map_resources.analyze as analyze
from pprint import pprint

TEST_BASE = ""
DATE_DEFAULT = '2015-01-01T00:00:00-04:00'
DATE_LEGACY = '1995-01-01T00:00:00-04:00'

class Element:
    def __init__(self, ctype, name, legacy):
        self.ctype = ctype
        self.name = name
        self.legacy = legacy
        idstr = "/" + ctype + "/" + name
        self.idstr = idstr
        self.ref = ""
        self.pocref = ""

    def get_ctype(self):
        return self.ctype

    def get_name(self):
        return self.name

    def get_legacy(self):
        return self.legacy

    def get_idstr(self):
        return self.idstr

    def get_pocref(self):
        return self.pocref

    def update_store(self, objstore):
        objstore[self.ctype][self.idstr] = {}
        objstore[self.ctype][self.idstr]['objID'] = self.idstr
        objstore[self.ctype][self.idstr][self.ctype] = {}
        if self.legacy:
            objstore[self.ctype][self.idstr][self.ctype]['registrationDate'] = DATE_LEGACY
        else:
            objstore[self.ctype][self.idstr][self.ctype]['registrationDate'] = DATE_DEFAULT
        objstore[self.ctype][self.idstr][self.ctype]['handle'] = self.name
        objstore[self.ctype][self.idstr][self.ctype]['name'] = self.name
        return objstore

    def addRef(self, objstore, e, refidx):
        base = e.get_idstr()
        key = base + "/" + self.ref
        if key not in objstore[self.ctype].keys():
            objstore[self.ctype][key] = {}
            objstore[self.ctype][key]['objID'] = key
            objstore[self.ctype][key][self.ref] = {}
            objstore[self.ctype][key][self.ref][refidx] = []
        objstore[self.ctype][key][self.ref][refidx].append({'@handle': self.name})
        return objstore


class OrgElement(Element):
    def __init__(self, name, legacy=False):
        Element.__init__(self, 'org', name, legacy)
        self.ref = "orgs"
        self.pocref = "orgPocLinkRef"

class ASNElement(Element):
    def __init__(self, asn, orgobj, legacy=False):
        name = "AS" + str(asn)
        Element.__init__(self, 'asn', name, legacy)
        self.ref = "asns"
        self.pocref = "asnPocLinkRef"
        self.asn = asn
        self.orgobj = orgobj

    def update_store(self, objstore):
        objstore = Element.update_store(self, objstore)
        # Add other data to ASN object
        objstore[self.ctype][self.idstr]['asn']['startAsNumber'] = self.asn
        objstore[self.ctype][self.idstr]['asn']['endAsNumber'] = self.asn
        objstore[self.ctype][self.idstr]['asn']['orgRef'] = {'@handle': self.orgobj.get_name()}
        # Add reference to self to org obj
        return self.addRef(objstore, self.orgobj, 'asnRef')

class NetElement(Element):
    def __init__(self, name, orgobj, start, end, cidr, legacy=False):
        Element.__init__(self, 'net', name, legacy)
        self.ref = "nets"
        self.pocref = "netPocLinkRef"
        self.orgobj = orgobj
        self.start = start
        self.end = end
        self.cidr = cidr

    def update_store(self, objstore):
        objstore = Element.update_store(self, objstore)
        # Add other data to Net object
        objstore[self.ctype][self.idstr]['net']['startAddress'] = self.start
        objstore[self.ctype][self.idstr]['net']['endAddress'] = self.end
        objstore[self.ctype][self.idstr]['net']['netBlocks'] = {
            'netBlock': {'cidrLength':self.cidr, 'startAddress':self.start, 'endAddress':self.end}
        }
        objstore[self.ctype][self.idstr]['net']['orgRef'] = {'@handle': self.orgobj.get_name()}
        # Add reference to self to org obj
        return self.addRef(objstore, self.orgobj, 'netRef')

class POCElement(Element):
    def __init__(self, name, org=None, asn=None, net=None, legacy=False):
        Element.__init__(self, 'poc', name, legacy)
        self.ref = "pocs"
        self.pocref = "pocLinkRef"
        self.org = org
        self.asn = asn
        self.net = net

    def update_store(self, objstore):
        objstore = Element.update_store(self, objstore)
        # Add other data to POC object
        objstore[self.ctype][self.idstr]['poc']['lastname'] = 'Lastname'
        objstore[self.ctype][self.idstr]['poc']['firstname'] = 'Firstname'
        if self.org:
            objstore = self.addPOCRef(objstore, self.org)
        if self.asn:
            objstore = self.addPOCRef(objstore, self.asn)
        if self.net:
            objstore = self.addPOCRef(objstore, self.net)
        return objstore
            
    def addPOCRef(self, objstore, e):
        objstore = self.addRef(objstore, e, self.pocref)
        objstore = e.addRef(objstore, self, e.get_pocref())
        return objstore


class DummyStore(fetch_whois.GenericStore):
    """Data Store with artificial values."""

    def __init__(self, store):
        fetch_whois.GenericStore.__init__(self, TEST_BASE)
        self.store = store

    def fetch(self, ctype, idstr):
        """Fetch data for the given ID string and collection type.

        Return pre-populated data

        Args:
            ctype (str): The collection type.
            idstr (str): The location reference for the whois object.

        Returns:
            A dict object representing the result.
        """
        if idstr not in self.store[ctype].keys():
            result = None
        else:
            result = self.store[ctype][idstr]
        return result

    def dump(self):
        pprint(self.store)

class Cluster():
    def __init__(self):
        self.store = {'asn':{}, 'poc':{}, 'net':{}, 'org':{}}

    def add_elements(self, elms):
        for e in elms:
            self.store = e.update_store(self.store)

    def get_store(self):
        return DummyStore(self.store)


class MapResourceTests(unittest.TestCase):
    """The main test driver."""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def runTest(self):
        pass

    def _get_state(self, o):
        c = o.get_collections(recurse=True)
        r = o.get_resources(recurse=True)
        l = o.get_links(recurse=True)
        x = o.get_limit_exceeded(recurse=True)
        t = o.get_tooltip(recurse=True)
        return (c, r, l, x, t)

    def _create_cluster_1(self):
        o = OrgElement("ORG-1")
        a = ASNElement(64512, o)
        n = NetElement("NET-1", o, '192.168.100.0', '192.168.100.255', '24')
        p = POCElement("POC-1", o, a, n)
        c = Cluster()
        c.add_elements([o, a, n, p])
        return c

    def _create_cluster_2(self):
        o = OrgElement("ORG-1")
        a = ASNElement(64512, o)
        n = NetElement("NET-1", o, '192.168.100.0', '192.168.100.255', '24')
        p1 = POCElement("POC-1", o, a, n)
        p2 = POCElement("POC-2", o)
        c = Cluster()
        c.add_elements([o, a, n, p1, p2])
        return c

    def _create_cluster_3(self):
        o1 = OrgElement("ORG-1")
        a1 = ASNElement(64512, o1)
        n1 = NetElement("NET-1", o1, '192.168.100.0', '192.168.100.255', '24')
        p1 = POCElement("POC-1", o1, a1, n1)
        o2 = OrgElement("ORG-2")
        a2 = ASNElement(64513, o2)
        n2 = NetElement("NET-2", o2, '192.168.101.0', '192.168.101.255', '24')
        p2 = POCElement("POC-2", o2, a2, n2)
        c = Cluster()
        c.add_elements([o1, a1, n1, p1, o2, a2, n2, p2])
        return c

    def _create_cluster_4(self):
        o1 = OrgElement("ORG-1")
        a1 = ASNElement(64512, o1)
        n1 = NetElement("NET-1", o1, '192.168.100.0', '192.168.100.255', '24')
        p1 = POCElement("POC-1", o1, a1, n1)
        o2 = OrgElement("ORG-2")
        a2 = ASNElement(64513, o2)
        n2 = NetElement("NET-2", o2, '192.168.101.0', '192.168.101.255', '24')
        p2 = POCElement("POC-2", o2, a2, n2)
        p3 = POCElement("POC-2", o1)
        c = Cluster()
        c.add_elements([o1, a1, n1, p1, o2, a2, n2, p2, p3])
        return c

    # All structures should be empty if the search handle does not exist
    def test_nonex(self):
        c = self._create_cluster_1()
        asc = fetch_whois.ASNCollection('AS1', store=c.get_store())
        asc.do_slurp()
        (c, r, l, x, t) = self._get_state(asc)
        self.assertFalse(c)
        self.assertFalse(r)
        self.assertFalse(l)
        self.assertFalse(x)
        self.assertFalse(t)

    # Verify that there is one element of each type for the cluster1. 
    def test_counts(self):
        c = self._create_cluster_1()
        asc = fetch_whois.ASNCollection('AS64512', store=c.get_store())
        asc.do_slurp()
        (c, r, l, x, t) = self._get_state(asc)
        for ctype in r.keys():
            self.assertEqual(len(r[ctype]), 1)

    # Verify that the node that has its dependency threshold exceeded
    # appears in the 'exceeded' array as well as in the tooltip list 
    def test_exceeded(self):
        c = self._create_cluster_2()
        asc = fetch_whois.ASNCollection('AS64512', store=c.get_store(), threshold=1)
        asc.do_slurp()
        (c, r, l, x, t) = self._get_state(asc)
        self.assertEqual(len(x), 1)
        self.assertEqual(len(t.keys()), 1)

    # The node with its dependency threshold exceeded should disappear
    # from the list if it is in the whitelist
    def test_whitelist(self):
        c = self._create_cluster_2()
        asc = fetch_whois.ASNCollection('AS64512', store=c.get_store(), threshold=1, whitelist=['ORG-1'])
        asc.do_slurp()
        (c, r, l, x, t) = self._get_state(asc)
        self.assertEqual(len(x), 0)
        self.assertEqual(len(t.keys()), 0)

    # Check if we can get to the result through the analyzer object
    def test_analyzer(self):
        c = self._create_cluster_1()
        objlist = {
            'AS64512' : 'asn'
        }
        a = analyze.WhoisAnalyzer(store=c.get_store())
        resob = a.analyze(objlist)
        (c, r, l, x, t) = self._get_state(resob)
        for ctype in r.keys():
            self.assertEqual(len(r[ctype]), 1)

    # Check if we generate the correct set of resource clusters
    def test_analyzer_clusters_separate(self):
        c = self._create_cluster_3()
        objlist = {
            'AS64512' : 'asn',
            'AS64513' : 'asn'
        }
        a = analyze.WhoisAnalyzer(store=c.get_store())
        a.analyze(objlist)
        (resources, l, x) = a.generate_clusters()
        self.assertEqual(len(resources), 2)

    def test_analyzer_clusters_merged(self):
        c = self._create_cluster_4()
        objlist = {
            'AS64512' : 'asn',
            'AS64513' : 'asn'
        }
        a = analyze.WhoisAnalyzer(store=c.get_store())
        a.analyze(objlist)
        (resources, l, x) = a.generate_clusters()
        self.assertEqual(len(resources), 1)

    # Check all reporting routines
    def test_analyzer_reporting(self):
        c = self._create_cluster_4()
        objlist = {
            'AS64512' : 'asn'
        }
        a = analyze.WhoisAnalyzer(store=c.get_store())
        a.analyze(objlist)

        oh = StringIO()
        a.generate_results(reportfile=oh)
        self.assertGreater(oh.len, 0)

        oh = StringIO()
        a.generate_results(jsonfile=oh)
        self.assertGreater(oh.len, 0)

        graphfile = "graph.png"
        a.generate_results(graphfile=graphfile)
        self.assertGreater(os.stat(graphfile).st_size, 0)
        os.remove(graphfile)

        oh = StringIO()
        a.generate_results(cjsonfile=oh)
        self.assertGreater(oh.len, 0)
        terselen = oh.len

        oh = StringIO()
        a.generate_results(cjsonfile=oh, extended=True)
        self.assertGreater(oh.len, terselen)
#        print oh.getvalue()


if __name__ == '__main__':
    unittest.main()
#    m = MapResourceTests()
#    m.test_exceeded()
    
