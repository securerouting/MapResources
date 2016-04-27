"""Query ARIN whois objects

This module provides the functionality to query the ARIN RESTful API
for all resource dependencies starting from the given ASN, POC, Org or
Net handle.

Attributes:
  verbose (boolean): Turns on verbosity of log messages.

"""
from pymongo import MongoClient, collection
from bson.objectid import ObjectId
from collections import defaultdict
from pprint import pprint
import urllib 
import requests
import xmltodict

###############################################################
# Define some constants

# ARIN REST API base URL
BASE = "http://whois.arin.net/rest" 

# Don't follow dependencies when the count is greater
# than this threshold
THRESHOLD = 25

###############################################################
# Globals

global verbose
verbose = False

###############################################################
# The following classes implement our data store
# The store can be one of the following types 
# 1) Generic: No caching, serves as our base class
# 2) Hash: Persistent for the process lifetime duration
# 3) DB: DB-based, therefore persistent on disk

class GenericStore:
    """Base class for all data stores with no caching support."""

    def __init__(self, base=BASE):
        self.base = base

    def get_idstr(self, typepfx, handle):
        """Determine the set of IDs for given type and handle.

        This is the default way of constructing an ID.

        Args:
            typepfx (str): The collection type.
            handle (str): The resource handle. 

        Returns:
            A tuple comprising the handle and
            a list of ID strings and collection type values.  
        """
        if typepfx == 'url' or typepfx == 'orgstr':
            raise Exception("'url' handle not supported for this store")
        idstr = self.base + "/" + typepfx + "/" + urllib.quote(str(handle))
        return (handle, [(typepfx, idstr)])

    def query(self, idstr):
        """Query the data store for the given ID string.

        This is the common query method for all types of data stores.

        Args:
            idstr (str): The ID string.

        Returns:
            A dict object representing the result.
        """
        print "Looking up " + idstr
        resp = requests.get(idstr)
        if resp.status_code != requests.codes.ok:
            if verbose:
                print "No data returned for " + idstr
            result = {}
            # Remember the fact that we already looked up this data
            result["objID"] = idstr
            return result
        xmltext = resp.text
        result = xmltodict.parse(xmltext)
        # Use a custom identifier
        result["objID"] = idstr
        return result

    def fetch(self, ctype, idstr):
        """Fetch data for the given ID string and collection type.

        No caching is done in this routine. Just query and return.

        Args:
            ctype (str): The collection type.
            idstr (str): The location reference for the whois object.

        Returns:
            A dict object representing the result.
        """
        result = self.query(idstr)
        return result

    def fetchAssociated(self, obj, idstr):
        """Fetch an object's associated data, given an ID string.

        Args:
            obj (str): The object for which we are seeking associated data.
            idstr (str): The ID string.

        Returns:
            A dict object representing the result.
        """
        return self.fetch(obj.get_type(), idstr)

class HashStore(GenericStore):
    """Implementation of a simple hash data store (non-persistent)."""

    def __init__(self, base=BASE):
        GenericStore.__init__(self, base)
        self.store = defaultdict(dict)

    def fetch(self, ctype, idstr):
        """Fetch data for the given ID string and collection type.

        First look at the hash for any matching data. If found return
        that data; if not fetch new data.
        """
        # Look for data in the hash
        if idstr in self.store[ctype].keys():
            return self.store[ctype][idstr]
        result = self.query(idstr)
        # Store any new data in the hash
        self.store[ctype][idstr] = result
        return result


class DBStore(GenericStore):
    """Wrapper around a MongoDB data store."""

    def __init__(self, dbhost, dbport, local=False):
        """Instantiate a MongoDB store object.

        Args:
            dbhost (str): The Database hostname.

            dbport (int): The Database port.

            local (boolean): If true, only use pre-cached values. That
                             is, issue no new queries.
        """
        GenericStore.__init__(self)
        # Use default host and port for our DB
        client = MongoClient(dbhost, dbport) 
        # DB handle
        self.db = client.whois
        # DB collection
        self.cols = {}
        self.local = local

    def find_collection(self, ctype):
        """Find the DB collection associated with the given object type.

        Args:
            ctype (str): The collection object type.

        Returns:
            The mongoDB collection object.
        """
        if not ctype in self.cols.keys():
            self.cols[ctype] = collection.Collection(self.db, ctype)
        return self.cols[ctype]

    def fetch(self, ctype, idstr):
        """Fetch data for the given ID string and collection type.

        First look at the MongoDB store for any matching data. If found return
        that data; if not, fetch new data but only if we are not
        limiting lookups to already-cached values.
        """
        # Find an existing element with the given ID
        if verbose:
            print "Checking store for " + idstr
        c = self.find_collection(ctype)
        result = c.find_one({"objID":idstr})
        if not result:
            if self.local:
                # Don't fetch any data
                result = {}
                result["objID"] = idstr
            else:
                # Query and add data
                result = self.query(idstr)
                oid = c.insert(result)
                #pprint(oid)
        return result


#######################################################################
# The following classes implement the different Whois object containers

# Base class, should not be instantiated directly
class WhoisCollection:
    """Base class for all Whois collection objects."""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """Base class constructor.

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip.
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        to be filtered.
            blacklist (list of string): Object handles that are 
                                        to be filtered.

        """
        self.collections = defaultdict(list)
        self.links = defaultdict(list)
        self.resources = defaultdict(list)
        self.tooltip = defaultdict(list)
        self.filtered = []
        self.attrib = {}
        self.attrib['shape'] = 'doublecircle'
        self.attrib['style'] = ""
        self.attrib['fillcolor'] = 'white'
        self.attrib['color'] = 'black'
        self.attrib['penwidth'] = 1
        self.origin_handle = origin_handle
        self.origin = origin

        # If some value is given directly use it first
        # Else look at the parent object
        # Else set it to None

        # Set the store
        if store:
            self.store = store
        elif origin:
            self.store = origin.get_store()
        else:
            self.store = None
        # Set the cache
        if cache:
            self.cache = cache
        elif origin:
            self.cache = origin.get_cache()
        else:
            self.cache = {}
        # Set the threshold
        if threshold:
            self.threshold = threshold
        elif origin:
            self.threshold = origin.get_threshold()
        else:
            self.threshold = THRESHOLD
        # Set the whitelist
        if whitelist:
            self.whitelist = whitelist
        elif origin:
            self.whitelist = origin.get_whitelist()
        else:
            self.whitelist = []
        # Set the blacklist
        if blacklist:
            self.blacklist = blacklist
        elif origin:
            self.blacklist = origin.get_blacklist()
        else:
            self.blacklist = []
        # Set the initial tooltip
        if tt:
            self.tooltip[self.origin_handle] = tt

    def do_slurp(self):
        """Entry point for looking up resource objects. """
        if not isinstance(self.origin_handle, unicode):
            self.slurp(unicode(self.origin_handle,"utf-8"))
        else:
            self.slurp(self.origin_handle)

    def get_data(self, ctype, idstr):
        """Get data corresponding to given ID string and collection type.

        First check if the data exists in the cache. If it doesn't then
        look for data in the data store.

        Args:
            ctype (string): Collection type.
            idstr (string): ID string.

        Returns:
            A tuple of two values, where the first is a boolean value
            that indicates whether the data was cached or not, and the
            second is the result dict object.
        """
        if idstr in self.cache.keys():
           return (False, self.cache[idstr])
        elif self.store:
           return (True, self.store.fetch(ctype, idstr))
        else:
           return (True, None)


    def fetchObj(self, typepfx, handle, cache=True):
        """Get data corresponding to given handle and collection type.

        This method first constructs the ID string(s) corresponding to
        the handle and then calls get_data() to get the actual result
        object. 

        Args:
            typepfx (string): Collection type.
            handle (string): Resource handle.
            cache (boolean): If true, any data returned by get_data() is cached. 

        Returns:
            A list of object tuples. Each object tuple contains three
            values: the first is whether the data was fresh (not cached)
            or not; the second, is the ID string, and the third is the
            result object.
        """
        objs = []
        if not self.store:
            return objs
        (r_handle, idstrlist) = self.store.get_idstr(typepfx, handle)
        if r_handle != handle:
            self.links[handle].append(r_handle)
        for (ctype, idstr) in idstrlist:
            (fresh, result) = self.get_data(ctype, idstr)
            if cache and fresh:
                self.cache[idstr] = result
            if result:
                self.resources[typepfx].append((handle, idstr))
                objs.append((fresh, idstr, result))
        return objs

    def fetchAssociatedObj(self, idstr):
        """Get associated data for given idstr.

        This method asks the data store for any associated objects. 

        Args:
            idstr (str): object ID str.

        Returns:
            A tuple with two values: the first is whether the data was
            cached or not; and the second is the actual result object.
        """
        if idstr in self.cache.keys() or not self.store:
            return (False, self.cache[idstr])
        result = self.store.fetchAssociated(self, idstr)
        self.cache[idstr] = result
        return (True, result)


    def slurp_common(self, p, idstr):
        """Common convenience function for data slurping.

        If we're presented with a dict, look for the handle in all
        list elements; if not, check in the provided list.
        Do not process those objects whose child collections have number
        of elements greater than a particular threshold.

        Args:
            p (str): the link reference to process.

            idstr (str): object ID str.

        Returns:
            None. 
        """
        if isinstance(p, dict): # We have a dict
            handle = p['@handle']
            self.slurp(handle)
        else: # We have a list
            if self.origin_handle in self.blacklist:
                self.filtered.append(self.origin_handle)
                return
            elif len(p) > self.threshold and self.origin_handle not in self.whitelist:
                # Don't follow a very long list
                # Note that we update the parent object
                self.origin.set_limit_exceeded(self.origin_handle, idstr, len(p))
                self.filtered.append(self.origin_handle)
                return
            for pi in p:
                handle = pi['@handle']
                self.slurp(handle)

    def add_collection(self, col):
        """Add a new associated ollection to the current object.

        Collections are indexed by the origin handle. There can be
        multiple collections per origin handle. As part of adding the
        collection also update the cache from the to-be-added collection
        to the main (parent) collection holder.

        Args:
            col (WhoisCollection): the collection object to be added.

        Returns:
            None. 
        """
        h = col.get_parent_handle()
        self.collections[h].append(col)
        # Update our cache with the given object's
        self.cache.update(col.get_cache())

    def get_collections(self, recurse=True):
        """Get list of collections associated with the given object. 

        Return all objects below and including the current one
        grouped by their handle.

        Args:
            recurse (boolean): return collection objects by traversing
                               all collections that are linked through
                               previous calls to add_collection().

        Returns:
            A dict of lists of WhoisCollection objects. The keys 
            of the dict are the origin handles that were used in the
            construction of the associated WhoisCollection objects.
        """
        ret = {}
        ret.update(self.collections)
        if recurse:
            for k in self.collections.keys():
                # Note that k is the parent handle
                for o in self.collections[k]:
                    n = o.get_collections()
                    for k in n.keys():
                        if k in ret.keys():
                            ret[k] = ret[k] + list(set(n[k]) - set(ret[k]))
                        else:
                            ret[k] = list(set(n[k]))
        return ret

    def add_link(self, handle):
        """Create a link between the current object and the given handle.

        Args:
            handle (str): the handle of the collection to link with.

        Returns:
            None. 
        """
        if self.origin_handle != handle:
            self.links[self.origin_handle].append(handle)

    def get_links(self, recurse=True):
        """Get the list of links associated with the given object. 

        For each object below and including the current node return
        the list of connected nodes.

        Args:
            recurse (boolean): return links by traversing all
                               collections that are linked through
                               previous calls to add_collection().

        Returns:
            A dict of lists of handles. The keys of the dict are the
            origin handles that were used in the construction of the
            associated WhoisCollection objects.
        """
        ret = {}
        ret.update(self.links)
        if recurse:
            for k in self.collections.keys():
                for o in self.collections[k]:
                    n = o.get_links()
                    for k in n.keys():
                        if k in ret.keys():
                            ret[k] = ret[k] + list(set(n[k]) - set(ret[k]))
                        else:
                            ret[k] = list(set(n[k]))
        return ret

    def get_resources(self, recurse=True):
        """Get the list of resources associated with the given object. 

        Args:
            recurse (boolean): return resources by traversing all
                               collections that are linked through
                               previous calls to add_collection().

        Returns:
            A dict of lists of resources. The keys are the
            resource types.
        """
        ret = {}
        ret.update(self.resources)
        if recurse:
            for k in self.collections.keys():
                for o in self.collections[k]:
                    n = o.get_resources()
                    for k in n.keys():
                        if k in ret.keys():
                            ret[k] = sorted(ret[k] + list(set(n[k]) - set(ret[k])))
                        else:
                            ret[k] = sorted(list(set(n[k])))
        return ret


    def add_tooltip(self, handle, msg):
        """Add a new tooltip to the object.

        Append a new tooltip to the list indexed by the given handle. 

        Args:
            handle (str): the handle to associate the tool-tip with.
            msg (str): the tool-tip message.

        Returns:
            None. 
        """
        if handle in self.tooltip.keys():
            self.tooltip[handle].append(msg)
        else:
            self.tooltip[handle] = [msg]

    def get_tooltip(self, recurse=True):
        """Get the list of tooltips associated with the given object. 

        Args:
            recurse (boolean): return tooltips by traversing all
                               collections that are linked through
                               previous calls to add_collection().

        Returns:
            A dict of lists of tooltips. The keys are the
            origin handles.
        """
        ret = {}
        ret.update(self.tooltip)
        if recurse:
            for k in self.collections.keys():
                for o in self.collections[k]:
                    n = o.get_tooltip()
                    for k in n.keys():
                        if k in ret.keys():
                            ret[k] = ret[k] + list(set(n[k]) - set(ret[k]))
                        else:
                            ret[k] = list(set(n[k]))
        return ret

    def set_limit_exceeded(self, handle, idstr, lim):
        """Set the object state to indicate too many dependencies.

        Args:
            handle (str): the handle against which the limit exceeded
                          state is to be associated. 

            idstr (str): the ID string that triggered the limit exceeded event.

            lim (int): the number of dependencies that were detected.

        Returns:
            None. 
        """
        msg = "Threshold exceeded for " + idstr + ":" + str(lim)
        self.add_tooltip(handle, msg)

    def get_filtered(self, recurse=True):
        """Get the list of handles that were filtered

        Args:
            recurse (boolean): traverse all collections that are linked
                               through previous calls to
                               add_collection().

        Returns:
            A lists of handles that were filtered.
        """
        ret = self.filtered
        if recurse:
            for k in self.collections.keys():
                for o in self.collections[k]:
                    n = o.get_filtered()
                    ret = ret + list(set(n) - set(ret))
        return ret

    def get_parent_handle(self):
        """Return the origin (parent) handle for the object.

        Returns:
            The string value for the origin handle. 
        """
        return self.origin_handle

    def get_parent(self):
        """Return the parent object for the object.

        Returns:
            The WhoisContainer object corresponding to the parent.
        """
        return self.origin

    def get_cache(self):
        """Return the cache structure for the collection object.

        Returns:
            A dict value that holds the cache information for the
            WhoisCollection object.
        """
        return self.cache

    def get_threshold(self):
        """Return the threshold for the collection object.

        Returns:
            An integer value that holds the threshold value.
        """
        return self.threshold

    def get_whitelist(self):
        """Return the whitelisted handles.

        Returns:
            List of object handle strings that are whitelisted from
            fitering. 
        """
        return self.whitelist

    def get_blacklist(self):
        """Return the blacklisted handles.

        Returns:
            List of object handle strings that are blacklisted. 
        """
        return self.blacklist

    def get_type(self):
        """Get the collection type for the given collection object.

        Returns:
            A str value corresponding to the type of the whois
            collection object.
        """
        return self.attrib['ctype'] 

    def fill_draw_attribs(self, node_h, a):
        """ Get different attributes of this collection.

        Returns:
            A dict structure that contains the following attributes for
            the collection object:

            shape: the shape to use in any graphical representation.
            style: the figure style, such as its filled status.
            fillcolor: the fillcolor to use.
            color: the color to use.
            penwidth: the penwidth to use.
        """
        a['shape'] = self.attrib['shape'] 
        if node_h in self.tooltip.keys():
            a['tooltip'] = "&#10;".join(map(str, self.tooltip[node_h]))
        a['style'] = self.attrib['style'] 
        a['fillcolor'] = self.attrib['fillcolor'] 
        a['penwidth'] = self.attrib['penwidth']
        a['color'] = self.attrib['color']
        # If this is the starting node use a double edge 
        if not self.get_parent():
            a['peripheries'] = 2

    def get_store(self):
        """Get the store associated with this object.

        Returns:
            The GenericStore object that is associated with the given
            collection object.
        """
        return self.store

    def subsume(self, col):
        """Subsume the new collection object.
   
        Merge various pertinent data associated with the new collection
        object into the current collection object.

        Args:
            col (WhoisCollection): the collection object that we want to subsume.

        Returns:
            None
        """
        self.cache = col.get_cache()
        self.collections.update(col.get_collections(False))
        self.links.update(col.get_links(False))
        self.tooltip.update(col.get_tooltip(False))
        # Special logic for resources, since the dict keys can overlap
        curres = self.resources
        newres = col.get_resources(False)
        for k in newres.keys():
            if k in curres.keys():
                self.resources[k] = curres[k] + list(set(newres[k]) - set(curres[k]))
            else:
                self.resources[k] = newres[k]


class POCCollection(WhoisCollection):
    """Point of Contact Resource Class."""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """Point of Contact container class constructor.

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        WhoisCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)
        self.attrib['shape'] = 'note'
        self.attrib['ctype'] = 'poc'
        #self.attrib['color'] = 'maroon' 
        self.attrib['penwidth'] = 3


    def slurp_set(self, base):
        """Find the POC handle and slurp data.
    
        POCs may be found in XML elements named pocLinkRef or pocRef.

        Args:
            base (str): The base URL for lookups.
        """
        idstr = base + "/pocs"
        (fresh, result) = self.fetchAssociatedObj(idstr)
        if fresh and result and 'pocs' in result.keys():
            # Query and store each poc
            if 'pocLinkRef' in result['pocs'].keys():
                p = result['pocs']['pocLinkRef']
                self.slurp_common(p, idstr)
            if 'pocRef' in result['pocs'].keys():
                p = result['pocs']['pocRef']
                self.slurp_common(p, idstr)


    def slurp(self, handle):
        """Look for all objects that can be reached from this POC container.
    
        POC collections may be comprised of Org, ASN and Net collections.

        Args:
            handle (str): The origin handle for the slurp operation.
        """
        self.add_link(handle)
        objs = self.fetchObj('poc', handle)
        for (fresh, idstr, result) in objs:
            # Make all relevant sub-queries
            if fresh and result:
                org = OrgCollection(handle, self)
                org.slurp_set(idstr)
                self.add_collection(org)
                asn = ASNCollection(handle, self)
                asn.slurp_set(idstr)
                self.add_collection(asn)
                net = NetCollection(handle, self)
                net.slurp_set(idstr)
                self.add_collection(net)

class URLCollection(POCCollection):
    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """URL container class constructor (ephemeral).

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        POCCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)

    def slurp(self, handle):
        """Look for all objects that can be reached from this URL.
    
        Look for the associated POCCollection object and perform the
        slurp operation over that object. 

        Args:
            handle (str): The origin handle for the slurp operation.
        """
        objs = self.fetchObj('url', handle, cache=False)
        for (fresh, idstr, result) in objs:
            if result and 'poc' in result.keys():
                handle_c = result['poc']['handle']
                self.links[handle].append(handle_c)
                if fresh:
                    poc = POCCollection(handle_c,
                            store=self.get_store(), cache=self.cache,
                            threshold=self.threshold,
                            whitelist=self.whitelist,
                            blacklist=self.blacklist)
                    poc.slurp(handle_c)
                    self.subsume(poc)


class OrgCollection(WhoisCollection):
    """ Organization Resouce Class"""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """Org container class constructor.

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        WhoisCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)
        self.attrib['shape'] = 'diamond'
        self.attrib['ctype'] = 'org'
        #self.attrib['color'] = 'blue' 
        self.attrib['penwidth'] = 3

    def slurp_set(self, base):
        """Find the Org handle and slurp data.
    
        Orgs may be found in XML elements named orgPocLinkRef or orgRef.

        Args:
            base (str): The base URL for lookups.
        """
        idstr = base + "/orgs"
        (fresh, result) = self.fetchAssociatedObj(idstr)
        if fresh and result and 'orgs' in result.keys():
            # Query and store each poc
            if 'orgPocLinkRef' in result['orgs'].keys():
                p = result['orgs']['orgPocLinkRef']
                self.slurp_common(p, idstr)
            if 'orgRef' in result['orgs'].keys():
                p = result['orgs']['orgRef']
                self.slurp_common(p, idstr)

    def slurp(self, handle):
        """Look for all objects that can be reached from this Org container.
    
        Org collections may be comprised of POC, ASN and Net
        collections.

        Args:
            base (str): The base URL for lookups.
        """
        self.add_link(handle)
        objs = self.fetchObj('org', handle)
        for (fresh, idstr, result) in objs:
            # Make all relevant sub-queries
            # XXX Not fetching customer (for org) since there is only cust id
            # XXX for a net block
            if fresh and result:
                poc = POCCollection(handle, self)
                poc.slurp_set(idstr)
                self.add_collection(poc)
                asn = ASNCollection(handle, self)
                asn.slurp_set(idstr)
                self.add_collection(asn)
                net = NetCollection(handle, self)
                net.slurp_set(idstr)
                self.add_collection(net)

class OrgstrCollection(OrgCollection):
    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """Orgstr container class constructor (ephemeral).

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        OrgCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)

    def slurp(self, handle):
        """Look for all objects that can be reached from this OrgName 
    
        Look for the associated OrgCollection object and perform the
        slurp operation over that object. 

        Args:
            handle (str): The origin handle for the slurp operation.
        """
        objs = self.fetchObj('orgstr', handle, cache=False)
        for (fresh, idstr, result) in objs:
            if result and 'org' in result.keys():
                handle_c = result['org']['handle']
                self.links[handle].append(handle_c)
                if fresh:
                    org = OrgCollection(handle_c,
                            store=self.get_store(), cache=self.cache,
                            threshold=self.threshold,
                            whitelist=self.whitelist,
                            blacklist=self.blacklist)
                    org.slurp(handle_c)
                    self.subsume(org)

class NetCollection(WhoisCollection):
    """Net Resource Class."""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """Net container class constructor.

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        WhoisCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)
        self.attrib['shape'] = 'box'
        self.attrib['ctype'] = 'net'

    def slurp_set(self, base):
        """Find the Net handle and slurp data.
    
        Net resources may be found in XML elements named netPocLinkRef
        or netRef.

        Args:
            base (str): The base URL for lookups.
        """
        idstr = base + "/nets"
        (fresh, result) = self.fetchAssociatedObj(idstr)
        if fresh and result and 'nets' in result.keys():
            # Query and store each poc
            if 'netPocLinkRef' in result['nets'].keys():
                p = result['nets']['netPocLinkRef']
                self.slurp_common(p, idstr)
            if 'netRef' in result['nets'].keys():
                p = result['nets']['netRef']
                self.slurp_common(p, idstr)

    def slurp(self, handle):
        """Look for all objects that can be reached from this Net container.
    
        Net collections may be comprised of POC or Org collections.

        Args:
            base (str): The base URL for lookups.
        """
        self.add_link(handle)
        objs = self.fetchObj('net', handle)
        for (fresh, idstr, result) in objs:
            # Make all relevant sub-queries
            if fresh and result:
                poc = POCCollection(handle, self)
                poc.slurp_set(idstr)
                self.add_collection(poc)
                orgHandle = None
                if 'orgRef' in result['net'].keys():
                    orgHandle = result['net']['orgRef']['@handle']
                elif 'orgHandle' in result['net'].keys():
                    orgHandle = result['net']['orgHandle']
                if orgHandle:
                    org = OrgCollection(handle, self)
                    org.slurp(orgHandle)
                    self.add_collection(org)
                # XXX Not following RDNS links
                # XXX Not following parent/ and children/ links

class CIDRCollection(NetCollection):
    """IP container class (ephemeral)."""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """CIDR container class constructor (ephemeral).

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        NetCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)

    def slurp(self, handle):
        """Look for all objects that can be reached from this CIDR block.
    
        Look for the associated NetCollection object and perform the
        slurp operation over that object. 

        Args:
            handle (str): The origin handle for the slurp operation
        """
        objs = self.fetchObj('cidr', handle, cache=False)
        for (fresh, idstr, result) in objs:
            if result and 'net' in result.keys():
                handle_c = result['net']['handle']
                self.links[handle].append(handle_c)
                if fresh:
                    net = NetCollection(handle_c,
                            store=self.get_store(), cache=self.cache,
                            threshold=self.threshold,
                            whitelist=self.whitelist,
                            blacklist=self.blacklist)
                    net.slurp(handle_c)
                    self.subsume(net)

class IPCollection(NetCollection):
    """IP container class (ephemeral)."""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """IP container class constructor (ephemeral).

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        NetCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)

    def slurp(self, handle):
        """Look for all objects that can be reached from this IP address.
    
        Look for the associated NetCollection object and perform the
        slurp operation over that object. 

        Args:
            handle (str): The origin handle for the slurp operation.
        """
        objs = self.fetchObj('ip', handle, cache=False)
        for (fresh, idstr, result) in objs:
            if result and 'net' in result.keys():
                handle_c = result['net']['handle']
                self.links[handle].append(handle_c)
                if fresh:
                    net = NetCollection(handle_c,
                            store=self.get_store(), cache=self.cache,
                            threshold=self.threshold,
                            whitelist=self.whitelist,
                            blacklist=self.blacklist)
                    net.slurp(handle_c)
                    self.subsume(net)


class ASNCollection(WhoisCollection):
    """ASN Resource Class"""

    def __init__(self, origin_handle, origin=None, store=None,
            cache=None, tt=None, threshold=None, whitelist=None,
            blacklist=None):
        """ASN container class constructor.

        Args:
            origin_handle (str): The handle that identifies the container.
            origin (WhoisCollection): The parent container object.
            store (GenericStore): The store associated with this collection object.
            cache (dict): Any pre-cached values.
            tt (str): An initial tooltip (message).
            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.
            whitelist (list of string): Object handles that are not
                                        filtered.
            blacklist (list of string): Object handles that are
                                        filtered.
        """
        WhoisCollection.__init__(self, origin_handle, origin, store,
                cache, tt, threshold, whitelist, blacklist)
        self.attrib['shape'] = 'ellipse'
        self.attrib['ctype'] = 'asn'

    def slurp_set(self, base):
        """Find the ASN handle and slurp data.
    
        ASN resources may be found in XML elements named asnPocLinkRef
        or asnRef.

        Args:
            base (str): The base URL for lookups.
        """
        idstr = base + "/asns"
        (fresh, result) = self.fetchAssociatedObj(idstr)
        if fresh and result and 'asns' in result.keys():
            # Query and store each poc
            if 'asnPocLinkRef' in result['asns'].keys():
                p = result['asns']['asnPocLinkRef']
                self.slurp_common(p, idstr)
            if 'asnRef' in result['asns'].keys():
                p = result['asns']['asnRef']
                self.slurp_common(p, idstr)

    def slurp(self, handle):
        """Look for all objects that can be reached from this ASN container.
    
        ASN collections may be comprised of POC and Org collections.

        Args:
            base (str): The base URL for lookups.
        """
        self.add_link(handle)
        objs = self.fetchObj('asn', handle)
        for (fresh, idstr, result) in objs:
            # Make all relevant sub-queries
            if fresh and result and 'asn' in result.keys():
                poc = POCCollection(handle, self)
                poc.slurp_set(idstr)
                self.add_collection(poc)
                orgHandle = None
                if 'orgRef' in result['asn'].keys():
                    orgHandle = result['asn']['orgRef']['@handle']
                elif 'orgHandle' in result['asn'].keys():
                    orgHandle = result['asn']['orgHandle']
                if orgHandle:
                    org = OrgCollection(handle, self)
                    org.slurp(orgHandle)
                    self.add_collection(org)


