"""Analyze and report on resource clusters.

This module analyzes the data that was fetched through the ARIN RESTful
API and generates reportable output. It also implements the helper class
that is used for processing Command line input to any driver scripts.

Attributes:
  verbose (boolean): Turns on verbosity of log messages.

"""
import sys
import networkx as net
from pprint import pprint
from collections import defaultdict
from bson import json_util
import matplotlib.pyplot as plt
from json2html import *
import StringIO
import argparse
import netaddr
import community
from random import randint

import map_resources.fetch_whois as fetch_whois
import map_resources.whois_rv_cmp as whois_rv_cmp

# Default graph layout
LAYOUT = 'neato'

# default values for MongoDB
DBHOST = 'localhost'
DBPORT = 27017

# Legacy resource was registered prior to this date 
LEGACY = '1997-12-22'

global verbose
verbose = False


class WhoisAnalyzer:
    """ Define a class for analyzing a list of collection objects. """

    def __init__(self, store=None, threshold=None, whitelist=None, blacklist=None):
        """Instantiate a WhoisAnalyzer object.

        Args:
            store (GenericStore): The store to use for fetching data.

            threshold (int): If the number of node dependencies exceed
                             this limit the dependencies are not
                             followed.

            whitelist (list of string): Object handles that are not
                                        to be filtered.

            blacklist (list of string): Object handles that are to be
                                        filtered. 
        """
        self.store = store
        self.threshold = threshold
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.messages = []
        self.starthandles = []
        self.resob = None

    def append_message(self, msg):
        """Append a new message to the analyzer object."""
        self.messages.append(msg)

    def get_messages(self):
        """Return messages."""
        return self.messages

    def get_resobj(self):
        """ Get the collection container object.
            
        Return Values:
            The WhoisCollection object that serves as the 
            handle to the collection container
        """
        return self.resob

    def fetch(self, ctype, loc):
        """ Fetch the data corresponding to the given type and loc str.

        If we have a collection object try fetching through that first
        in order to get the benefit of caching. Otherwise look at the
        data store

        Args:
            ctype (str): Collection type.
            loc (str): The ID string.

        Returns:
            The result object structure.
        """
        if self.resob:
            (fresh, res) = self.resob.get_data(ctype, loc)
            return res 
        elif self.store:
            return self.store.fetch(ctype, loc)
        else:
            return None

    def process_new_collection(self, t, h, comment=None):
        """ Process a new collection of given type and handle.

        Create a new collection object with the given type. Reuse the
        cache and the data store if available, but dont link to any
        other collection object. Finally, subsume the resulting object
        into the main collection container object within self.

        Args:
            t (str): Collection type.
            h (str): The collection handle.

        Returns:
            None.
        """
        tt = []
        if comment:
            tt.append(comment)

        if self.resob:
            cache = self.resob.get_cache()
        else:
            cache = {}

        if t == 'poc':
            o = fetch_whois.POCCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'asn':
            o = fetch_whois.ASNCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'org':
            o = fetch_whois.OrgCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'net':
            o = fetch_whois.NetCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'cidr':
            o = fetch_whois.CIDRCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'ip':
            o = fetch_whois.IPCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'url':
            o = fetch_whois.URLCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        elif t == 'orgstr':
            o = fetch_whois.OrgstrCollection(h, store=self.store,
                    cache=cache, tt=tt, threshold=self.threshold,
                    whitelist=self.whitelist, blacklist=self.blacklist)
        if o:
            self.starthandles.append(h)
            o.do_slurp()
            if self.resob:
                self.resob.subsume(o)
            else:
                self.resob = o 

    def analyze(self, objlist):
        """ Analyze a list of handles.

        Each handle in the list is used as a starting point for the
        collection of resources through the process_new_collection()
        method. 

        Args:
            objlist (dict): A dict of handles->type mappings.

        Returns:
            None.
        """
        for k in objlist.keys():
            # The dict key corresponds to the resource handle
            # The dict value corresponds to the resource 'type'
            self.process_new_collection(objlist[k], k)

        return self.resob

    def generate_clusters(self):
        """Group resources according to their subgraphs.

        Returns:
            A tuple consisting of a dict of resources, a dict of links
            in the graph and the list of handles that were filtered.
        """
        if not self.resob:
            return (None, None, None)
        r = self.resob.get_resources()
        x = self.resob.get_filtered()
        l = self.resob.get_links()
        communities = defaultdict(int)
        # Filter the links to nodes that are on our filter list 
        lfilt = defaultdict(list)
        for k in l.keys():
            if k not in x:
                lfilt[k] = [e for e in l[k] if e not in x]
        G = net.from_dict_of_lists(lfilt)
        graphs = net.connected_component_subgraphs(G)
        resources = []
        links = defaultdict(list)
        # Just pick the subgraphs and the links that are relevant
        for g in graphs:
            if g.size() == 0:
                continue
            parts = community.best_partition(g) 
            c = defaultdict(list)
            relevant = False
            for n in g.nodes():
                if n in self.starthandles:
                    relevant = True
                for t in r.keys():
                    for (handle, idstr) in r[t]:
                        if n == handle:
                            c[t].append((handle, idstr))
                            break
            if relevant:
                resources.append(c)
                for (s, d) in g.edges():
                    links[s].append(d)
                    communities[s] = parts.get(s)
                    communities[d] = parts.get(d)
        return (resources, links, x, communities)

    def pack(self, resources, links, filtered):
        """Pack resource and links into a dict.

        Args:
            resources (dict): A dict of resources indexed by type
            links (dict): A dict of links
            filtered (list): A list of handles that are to be filtered

        Returns:
            A dict that has 'resources' and 'links' as two of its keys.
        """
        clust_res = {}
        clust_res['resources'] = resources
        clust_res['links'] = links    
        clust_res['filtered'] = filtered    
        return clust_res

    def unpack(self, clustobj):
        """Unpack a dict containing resources and links.

        Args:
            clustobj(dict): A dict that has 'resources' and 'links' as
                            two of its keys.

        Returns:
            A tuple of three elements:
                A dict of resources indexed by type
                A dict of links
                A list of handles that are to be filtered
        """
        return (clustobj['resources'], 
                clustobj['links'],
                clustobj['filtered'])


    def generate_results(self, options, rvf=None):
        """Generate various result components.

        The different result components can include a report file, a JSON
        structure with cluster information, a Graphviz graph and a plot
        of the graph using matplotlib.

        Args:
            options(dict):  A dict containing the following parameters:

                reportfile(file handle): If not None, the target file to
                                         write the HTML report into.

                jsonfile(file handle) : The target file for raw jason
                                        resource information.

                cjsonfile(file handle) : The target file for jason
                                        cluster information.

                showgraph(boolean): If True, display network graph plot
                                    using matplotlib.

                graphfile(filehandle): If True, write graphviz image to
                                        this file.

                extended(boolean): If True produce extended details.

            rvf(RouteViewsFetcher): If not None, use this object to
                                    augment report with RouteViews
                                    derived information.

        Returns:
            None.
        """
        if not self.resob or not options:
            print "No report to generate"
            return

        r = ResourceReporter(self)

        if verbose:
            r.write_cluster_summary(self.messages)

        if options['jsonfile']:
            r.write_raw_json(options['jsonfile'])

        if options['cjsonfile']:
            r.write_cluster_json(options['cjsonfile'],
                    options['extended'])

        if options['reportfile']:
            r.write_report(options['reportfile'],
                    clusterplot=options['clusterplot'],
                    clustergraph=options['clustergraph'],
                    extended=options['extended'], rvf=rvf)

        if options['graphfile']:
            r.plot_graph(options['graphfile'])

        if options['showgraph']:
            r.display_graph()


class WhoisObjectFormatter:
    """ A class that allows us to format data received from whois."""

    def __init__(self, getter):
        """ Constructor

            Args:
                getter(Object): An object that implements the fetch() method
                                for returning whois data. Currently the
                                only two classes that implement this
                                method are GenericStore (and its
                                subclasses) and WhoisAnalyzer 

        """
        self.getter = getter

    def get_netinfo(self, loc, rvf=None):
        """Generate net info.

        Build a dict structure that contains information such as the
        registration date, the different netblocks, and the network
        handle. Also fetch information from the routing table if we have
        access to a Route Views database.

        Args:
            loc(str): The object identifier.

            rvf(RouteViewsFetcher): If not None, fetch information such
                                    as routed netbocks and origination
                                    AS in order to determine if any
                                    network resources are originated by
                                    resources in a different cluster.

        Returns:
            A dict structure with the following keys:
                'handle': network handle
                'regstration': registration date
                'netblocks': a JSONized string of a list of network blocks
                'routed': a JSONized string of a list of routed network blocks
        """
        resobj = {}
        obj = self.getter.fetch('net', loc)
        if obj and 'net' in obj.keys():
            resobj['handle'] = obj['net']['handle']
            resobj['registrationDate'] = obj['net']['registrationDate']
            if resobj['registrationDate'] < LEGACY:
                resobj['legacy'] = True
            else:
                resobj['legacy'] = False
            # Strip leading 0s
            startAdd = '.'.join(y if y != "" else '0' for y in (x.lstrip('0') for x in obj['net']['startAddress'].split('.')))
            endAdd = '.'.join(y if y != "" else '0' for y in (x.lstrip('0') for x in obj['net']['endAddress'].split('.')))
            resobj['cidrs'] = [str(c) for c in netaddr.iprange_to_cidrs(netaddr.IPAddress(startAdd), netaddr.IPAddress(endAdd))]
            #resobj['netBlocks'] = json_util.dumps(obj['net']['netBlocks'])
            resobj['name'] = obj['net']['name']

            # Check for blocks in route views
            if rvf:
                nblist = []
                rows = rvf.find_netblocks(startAdd, endAdd)
                for row in rows:
                    nb = {}
                    nb['prefix'] = row[0]
                    # Add the 'AS' prefix
                    nb['lastAS'] = "AS" + str(row[1])
                    nb['inCluster'] = False
                    for cid in sorted(self.clusterinfo.keys()):
                        if 'asn' in self.clusterinfo[cid].keys():
                            asnlist = [h for (h, loc) in self.clusterinfo[cid]['asn']]
                            if nb['lastAS'] in asnlist:
                                nb['inCluster'] = True
                                break
                    nblist.append(nb)
                if len(nblist) > 0:
                    resobj['routed'] = json_util.dumps(nblist)
        return resobj

    def get_orginfo(self, loc):
        """Generate org info.

        Build a dict structure that contains organization related
        information. 

        Args:
            loc(str): The object identifier.

        Returns:
            A dict structure with the following keys:
                'handle': organizational handle
        """
        resobj = {}
        obj = self.getter.fetch('org', loc)
        if obj and 'org' in obj.keys():
            resobj['handle'] = obj['org']['handle']
            resobj['registrationDate'] = obj['org']['registrationDate']
            if resobj['registrationDate'] < LEGACY:
                resobj['legacy'] = True
            else:
                resobj['legacy'] = False
            resobj['name'] = obj['org']['name']
        return resobj

    def get_pocinfo(self, loc):
        """Generate poc info.

        Build a dict structure that contains Point of Contact related
        information. 

        Args:
            loc(str): The object identifier.

        Returns:
            A dict structure with the following keys:
                'handle': POC handle
        """
        resobj = {}
        obj = self.getter.fetch('poc', loc)
        if obj and 'poc' in obj.keys():
            resobj['handle'] = obj['poc']['handle']
            resobj['registrationDate'] = obj['poc']['registrationDate']
            if resobj['registrationDate'] < LEGACY:
                resobj['legacy'] = True
            else:
                resobj['legacy'] = False
            if 'companyName' in obj['poc'].keys():
                resobj['companyName'] = obj['poc']['companyName']
            resobj['name'] = ""
            if 'lastName' in obj['poc'].keys():
                resobj['name'] = obj['poc']['lastName']
            if 'firstName' in obj['poc'].keys():
                resobj['name'] = resobj['name'] + ", " + obj['poc']['firstName']
            if 'phones' in obj['poc'].keys():
                resobj['phones'] = obj['poc']['phones'] 
            if 'emails' in obj['poc'].keys():
                resobj['emails'] = obj['poc']['emails'] 
        return resobj

    def get_asninfo(self, loc):
        """Generate asn info.

        Build a dict structure that contains ASN related
        information. 

        Args:
            loc(str): The object identifier.

        Returns:
            A dict structure with the following keys:
                'handle': ASN handle
        """
        resobj = {}
        obj = self.getter.fetch('asn', loc)
        if obj and 'asn' in obj.keys():
            resobj['handle'] = obj['asn']['handle']
            resobj['registrationDate'] = obj['asn']['registrationDate']
            if resobj['registrationDate'] < LEGACY:
                resobj['legacy'] = True
            else:
                resobj['legacy'] = False
            resobj['name'] = obj['asn']['name']
        return resobj


class ResourceReporter:
    """ This class formats cluster information for reporting."""

    def __init__(self, analyzer, resources=None, links=None, filtered=None):
        """ Instantiate a ResourceReporter object.

        Get aggregated resources and associate each cluster with an ID.
        If no cluster information is passed through the resources, links
        and filtered parameter, generate cluster information from the
        analyzer object.

        Args:
            analyzer (WhoisAnalyzer): The WhoisAnalyzer object.
            resources (dict): The cluster information to report about.
            links (dict): The links associated with the clusters.
            filtered (list): The list of handles that are to be filtered.
        """
        self.analyzer = analyzer
        # Identify resource information through the analyzer object first
        (self.resources, self.links, self.filtered, self.communities) = self.analyzer.generate_clusters()
        # Override with any values provided as params
        if resources:
            self.resources = resources
        if links:
            self.links = links
        if filtered:
            self.filtered = filtered

        self.clusterinfo = {}
        cid = 0
        if self.resources:
            for c in self.resources:
                self.clusterinfo[cid] = defaultdict(list)
                for k in c.keys():
                    for (h, loc) in c[k]:
                        # Save the handles
                        self.clusterinfo[cid][k].append((h, loc))
                cid += 1


    def plot_resources(self, plotfile=None):
        """Scatter Plot number of URLs and IPs in each cluster.

        Produce a Scatter Plot of the number of resources of each type
        in each cluster. Annotate the top 10 clusters in terms of
        resource density.

        Args:
            plotfile (str, default=None): Graph file to write to

        Returns:
            A base64 encoded image of the scatter plot.
        """
        polar = True
        x = []
        y = defaultdict(list)
        for cid in self.clusterinfo.keys():
            x.append(cid)
            for rtype in ('asn', 'poc', 'org', 'net', 'cidr', 'ip', 'url'):
                y[rtype].append(len(self.clusterinfo[cid][rtype]))

        fig = plt.figure(figsize=(12,8))
        fig.suptitle("Resource Aggregation (Total clusters = " + str(len(x)) + ")")

        offset = 240
        for rtype in ('asn', 'poc', 'org', 'net', 'cidr', 'ip', 'url'):
            offset += 1
            ax = plt.subplot(offset, polar=polar)
            ax.set_title(rtype + " per cluster")
            ax.set_xticks([])
            # annotate the top 10
            alist = sorted(range(len(y[rtype])), key=lambda i: y[rtype][i], reverse=True)[:10]
            for i in alist:
                ax.annotate(str(i), (x[i],y[rtype][i]), color='red')
            # For size add 1 to avoid divide by 0 issues
            s = [i+1 for i in y[rtype]]
            c = plt.scatter(x, y[rtype], s=s, cmap=plt.cm.hsv)
            c.set_alpha(0.75)

        #plt.show()
        if plotfile:
            plt.savefig(plotfile)
        sio = StringIO.StringIO()
        plt.savefig(sio, format='png')
        return sio.getvalue().encode("base64").strip()

    def get_agraph(self, G, o):
        """Generate a Graphviz Agraph from graph information.

        Produce the Agraph from the networkx object. Also set node
        attributes from the values stored in the different
        WhoisCollection objects.

        Args:
            G(Graph): A networkx graph object.
            o(dict): A dict of object collections indexed by the origin handle.

        Returns:
            A graphviz Agraph.
        """
        # Add the nodes that were filtered
        #G.add_nodes_from(self.filtered)
        A = net.to_agraph(G)
        cmaplen = len(list(set(self.communities.values())))
        colors = ['#%06X' % randint(0, 0xFFFFFF) for _ in range(cmaplen)]
        for node_h in G.nodes():
            n = A.get_node(node_h)
            if node_h in o.keys():
                for obj in o[node_h]:
                    # We need the parent object, since that's what the
                    # handle points to
                    pobj = obj.get_parent()
                    if pobj:
                        pobj.fill_draw_attribs(node_h, n.attr)
                    n.attr['style'] = 'filled'
                    n.attr['fillcolor'] = colors[self.communities[node_h]] + ":white"
                    # All parent objects in the list will be the same
                    break
        return A

    def display_graph(self):
        """Display the resource graph using matplotlib."""
        l = self.links
        G = net.from_dict_of_lists(l)
        net.set_node_attributes(G, 'community', self.communities)
        # Display the graph using matplotlib
        labels = {}
        for node_h in G.nodes():
            labels[node_h] = node_h
        pos = net.graphviz_layout(G, prog=LAYOUT)
        net.draw(G, pos=pos, node_size=40)
        for node_h in labels:
            plt.annotate(labels[node_h], xy=pos[node_h])
        plt.show()

    def plot_graph(self, outputfile=None):
        """Build a graph of whois resources.

        Use graphviz to build the graph. Default format is neato
        The graph format is either png or svg.
        An svg image can show tooltips.

        Args:
            outputfile(file handle): If not None, write graph to this file.    

        Returns:
            A base64 encoded image of the whois resource graph.
        """
        resob = self.analyzer.get_resobj()
        if not resob:
            return None
        l = self.links
        G = net.from_dict_of_lists(l)
        o = resob.get_collections()
        A = self.get_agraph(G, o)
#        A.layout(prog=LAYOUT, args='-Goverlap=false -Gsize=12,8\!')
        #A.layout(prog=LAYOUT, args='-Goverlap=false')
        A.layout(prog=LAYOUT, args='-Goverlap=false -Gsplines=true')
#       print A.to_string()
        if outputfile:
            A.draw(outputfile)
        # Return the base64 encoded image
        sio = StringIO.StringIO()
        A.draw(sio, format='png')
        return sio.getvalue().encode("base64").strip()

    def get_clusterinfo(self, extended=False, rvf=None):
        """Return cluster info.

        Build a list of cluster information along with relevant network
        information for reporting.

        Args:
            extended(boolean): If True produce additional details.

            rvf(RouteViewsFetcher): If not None, fetch information from
                                    a RouteViews database to augment
                                    reported cluster information.

        Returns:

            A dict that contains for each cluster, a list of resources
            against each resource type.
        """
        clust = {}
        for c in sorted(self.clusterinfo.keys()):
            cid = "clusterID(" + str(c) + ")"
            clust[cid] = {}
            for k in self.clusterinfo[c].keys():
                clust[cid][k] = defaultdict(list)
                for (h, loc) in self.clusterinfo[c][k]:
                    if not extended:
                        clust[cid][k]['resources'].append(h)
                    else:
                        # Always try to get whois information through the analyze object
                        # This ensures that we take advantage of any caching. 
                        f = WhoisObjectFormatter(self.analyzer)
                        if k == 'net':
                            obj = f.get_netinfo(loc, rvf)
                        elif k == 'org':
                            obj = f.get_orginfo(loc)
                        elif k == 'poc':
                            obj = f.get_pocinfo(loc)
                        elif k == 'asn':
                            obj = f.get_asninfo(loc)
                        elif k == 'cidr':
                            obj = f.get_netinfo(loc)
                        elif k == 'url':
                            obj = f.get_pocinfo(loc)
                        else:
                            obj = {}
                        if obj:
                            # Fix the handle since we might have
                            # multiple ASNs that are part of the same block
                            obj['handle'] = h
                            clust[cid][k]['resources'].append(obj)

                clust[cid][k]['length'] = len(clust[cid][k]['resources'])
        # { cid -> { URLs | IPaddresses| Orgs | POCs | ASNs | Nets}}
        return clust

    def get_raw_clusterinfo(self):
        """Get the raw cluster information

        Returns:
            A tuple consisting of a dict of resources, a dict of links
            in the graph and the list of handles whose that were
            filtered.
        """
        return (self.resources, self.links, self.filtered)


    def write_raw_json(self, jh):
        """Write the raw resource information in json format.

        Args:
            jh(file handle): The target file for the JSON data. 

        Returns:
            None.
        """
        if jh:
            clust_res = self.analyzer.pack(self.resources, self.links, self.filtered)
            clust_json = json_util.dumps(clust_res)
            jh.write(clust_json)

    def write_cluster_json(self, jh, extended=True):
        """Write the cluster information in json format.

        Args:
            jh(file handle): The target file for the JSON data. 

        Returns:
            None.
        """
        if jh:
            report = self.get_clusterinfo(extended)
            clust_json = json_util.dumps(report)
            jh.write(clust_json)

    def write_cluster_summary(self, messages):
        """Write the cluster summary information.

        Args:
            messages(array of strings): A list of messages associated
                                        with the clusters.

        Returns:
            None.
        """
        if messages:
            print "Notes:"
            print "\n".join(map(str, messages))

        if self.filtered:
            print "Filtered the following nodes" + str(self.filtered)
            resob = self.analyzer.get_resobj()
            if resob:
                tooltips = resob.get_tooltip()
                for m in self.filtered:
                    if m in tooltips.keys():
                        for t in tooltips[m]:
                            print m + ":" + t

        i = 0
        for c in self.resources:
            print "Resources for cluster " + str(i) + ":"
            i += 1
            for k in c.keys():
                print "\t\tResource Type: " + k
                for (h, loc) in c[k]:
                    print "\t\t\t" + h + "\t" + "[" + loc + "]" 


    def write_report(self, rh, clusterplot=False, clustergraph=False, extended=False, rvf=None):
        """Write cluster info

        Args:
            rh(file handle): The target file for the HTML data. 

            clusterplot(boolean): If True, generate and write cluster
                                  plot information to report.

            clustergraph(boolean): If True, generate and write network
                                   resource information to report.

            extended(boolean): If True produce additional details.

            rvf(RouteViewsFetcher): If not None, use this object to
                                    augment report with RouteViews
                                    derived information.

        Returns:
            None.
        """
        if rh:
            if clusterplot:
                image = self.plot_resources()
                img_tag = '<img src="data:image/png;base64,{0}">'.format(image)
                rh.write(img_tag)

            if clustergraph:
                image = self.plot_graph()
                img_tag = '<img src="data:image/png;base64,{0}">'.format(image)
                rh.write(img_tag)

            rh.write("<br><br><br><h1>ARIN Whois Terms Of Use:</h1>")
            rh.write("<h3><a href='https://www.arin.net/whois_tou.html'>https://www.arin.net/whois_tou.html</a></h3>")

            messages = self.analyzer.get_messages()
            if len(messages) > 0:
                rh.write("<br><h1>Notes:</h1><br/>")
                rh.write("<ul>")
                for m in messages:
                    rh.write("<li>")
                    rh.write(m)
                    rh.write("</li>")
                rh.write("</ul>")
                rh.write("<br/>")

            resob = self.analyzer.get_resobj()
            if resob:
                tooltips = resob.get_tooltip()
            else:
                tooltips = {}
            if len(self.filtered) > 0:
                rh.write("<br><h1>Filtered the following:</h1><br/>")
                rh.write("<ul>")
                for m in self.filtered:
                    rh.write("<li>")
                    rh.write(m)
                    if m in tooltips.keys():
                        rh.write("<ul>")
                        for t in tooltips[m]:
                            rh.write("<li>")
                            rh.write(t)
                            rh.write("</li>")
                        rh.write("</ul>")
                    rh.write("</li>")
                rh.write("</ul>")
                rh.write("<br/>")

            rh.write("<br><h1>Resources:</h1><br/>")
            report = self.get_clusterinfo(extended, rvf)
            #result = json_util.dumps(report)
            #rh.write(result)
            json = json2html.convert(json=report)
            rh.write(json)



class WhoisOptParser:
    """Class to parse options related to any whois interfacing script."""

    def __init__(self, prog):
        """Constructor for the WhoisOptParser class.

        Initialize all base options.

        Args:
            prog(str): Name of the program
        """
        parser = argparse.ArgumentParser(prog=prog)
        parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
        parser.add_argument("-a", "--asn", help="Start from the given ASN handle", action='append')
        parser.add_argument("-p", "--poc", help="Start from the given POC handle", action='append')
        parser.add_argument("-o", "--org", help="Start from the given Org handle", action='append')
        parser.add_argument("-n", "--net", help="Start from the given Net handle", action='append')
        parser.add_argument("-c", "--cidr", help="Start from the given CIDR block", action='append')
        parser.add_argument("-i", "--ip", help="Start from the given IP address", action='append')
        parser.add_argument("-u", "--url", help="Start from the given domain", action='append')
        parser.add_argument("-s", "--orgstr", help="Start from the given org string", action='append')
        parser.add_argument("-L", "--resourcelist", help=self.parse_objs_from_file.__doc__, type=argparse.FileType('r'))
        parser.add_argument("-j", "--jsonfile", help="Output raw resource information in json format", type=argparse.FileType('w'))
        parser.add_argument("-J", "--cjsonfile", help="Output cluster information in json format", type=argparse.FileType('w'))
        parser.add_argument("-e", "--extended", help="Display detailed information", action='store_true')
        self.parser = parser
        self.add_stores()

    def get_parser(self):
        """Return the parser associated with this object."""
        return self.parser

    def host_port(self, s):
        """A simple type for a host:port identifier
        
        Throws argparse.ArgumentTypeError if the provided string is not
        formated as hostname:port.

        Args:
            s (str): a string of the form hostname:port

        Returns:
            The host(str) and port(int) tuple.
        """
        try:
            x, y = map(str, s.split(':'))
            return x, int(y)
        except:
            raise argparse.ArgumentTypeError("Host/Port must be host:port")

    def add_stores(self):
        """Register the options associated with different data store types."""
        group = self.parser.add_mutually_exclusive_group()
        group.add_argument("-X", "--nostore", help="Do not use any data store", action="store_true")
        group.add_argument("-H", "--hashstore", help="Use a hash store", action="store_true")
        group.add_argument("-D", "--dbstore", help="Use a DB store", type=self.host_port)

    def parse_objs_from_file(self, rsrcfile):
        """Extract resource handles from the given file.

        Each line of the file should be formatted as <type>:<value>,
        where the different supported types are 'asn', 'poc', 'org',
        'net', 'cidr', 'ip' and 'url'.  

        Args:
            rsrcfile(file handle): 

        Return Values:
            A dict object containing a mapping between
            the resource handle and the resource type.
        """
        objlist = {}
        for line in rsrcfile:
            line = line.rstrip()
            (rtype, val) = line.split(':', 1)
            if rtype in ('asn', 'poc', 'org', 'net', 'cidr', 'ip', 'url'):
                objlist[val] = rtype
            else:
                print "Unknown token : " + line
                sys.exit(2)
        return objlist

    def parse_objs(self, p):
        """Extract object handles and types from provided options.

        The object handle could come from a file or from the relevant
        option associated with each resource type.

        Args:
            p(Namespace): Contains various command line parameters.

        Returns:
            A dict objects whose keys correspond to the different handle
            identifiers and whose values correspond to the resource
            type.
        """
        objlist = {}
        if p.resourcelist:
            objlist = self.parse_objs_from_file(p.resourcelist)
        if p.asn:
            objd = { o : 'asn' for o in p.asn}
            objlist.update(objd)
        if p.poc:
            objd = { o : 'poc' for o in p.poc}
            objlist.update(objd)
        if p.org:
            objd = { o : 'org' for o in p.org}
            objlist.update(objd)
        if p.net:
            objd = { o : 'net' for o in p.net}
            objlist.update(objd)
        if p.cidr:
            objd = { o : 'cidr' for o in p.cidr}
            objlist.update(objd)
        if p.ip:
            objd = { o : 'ip' for o in p.ip}
            objlist.update(objd)
        if p.url:
            objd = { o : 'url' for o in p.url}
            objlist.update(objd)
        if p.orgstr:
            objd = { o : 'orgstr' for o in p.orgstr}
            objlist.update(objd)

        return objlist

    def parse_store(self, p):
        """Extract the store type from provided options.

        Args:
            p(Namespace): Contains various command line parameters.

        Returns:
            A GenericStore object corresponding to the selected data
            store type.
        """
        if p.nostore:
            store = fetch_whois.GenericStore()
        elif p.hashstore:
            store = fetch_whois.HashStore() 
        elif p.dbstore:
            dbhost, dbport = p.dbstore
            store = fetch_whois.DBStore(dbhost, dbport)
        else:
            store = fetch_whois.DBStore(DBHOST, DBPORT)
        return store

    def parse_opts(self, p):
        """Parse the list of options given in the parser namespace.

        Args:
            A namespace containing the different parsed options.

        Returns:
            A dict structure that contains different analyzer options.
        """
        opts = {}

        opts['verbose'] = p.verbose
        if p.verbose:
            global verbose
            verbose = True
            fetch_whois.verbose = True
            whois_rv_cmp.verbose = True

        opts['objlist'] = self.parse_objs(p)
        opts['store'] = self.parse_store(p)

        if p.extended:
            opts['extended'] = True
        else:
            opts['extended'] = False

        if p.jsonfile:
            opts['jsonfile'] = p.jsonfile
        else:
            opts['jsonfile'] = None

        if p.cjsonfile:
            opts['cjsonfile'] = p.cjsonfile
        else:
            opts['cjsonfile'] = None

        return opts

    def parse(self, argv):
        """Parse the list of options.

        Args:
            A list of arguments provided in argv.

        Returns:
            A dict structure that contains different analyzer options.
        """
        p = self.parser.parse_args(argv)
        return self.parse_opts(p)

    def get_help(self):
        """Return the formatted help text.

        Returns:
            Str value containing formatted help text.
        """
        return self.parser.format_help()


class AnalyzeOptExtension():
    """Class to parse options related to any analysis driver script."""

    def __init__(self, base):
        """Constructor for the AnalyzeOptExtension class.

        Add arguments that are specific to the Analyzer.

        Args:
            base(WhoisOptParser): The WhoisOptParser object associated with this extension.
        """
        self.base = base
        self.parser = self.base.get_parser()
        self.parser.add_argument("-t", "--threshold", help="Maximum number of dependencies to follow", action='store', type=int, default=25)
        self.parser.add_argument("-w", "--whitelist", help="Whitelisted handles", action='append')
        self.parser.add_argument("-b", "--blacklist", help="Blacklisted handles", action='append')
        self.parser.add_argument("-S", "--showgraph", help="Dsplay the graph", action='store_true')
        self.parser.add_argument("-g", "--graphfile", help="Output graph image", type=argparse.FileType('w'))
        self.parser.add_argument("-r", "--reportfile", help="Output report", type=argparse.FileType('w'))
        self.parser.add_argument("-G", "--clustergraph", help="Include graph image in report", action='store_true')
        self.parser.add_argument("-P", "--clusterplot", help="Include resource plot in report", action='store_true')
        self.parser.add_argument("-R", "--rvdb", help="Check against given Route Views Database file", type=str)

    def parse(self, argv):
        """Parse the list of options.

        Args:
            A list of arguments provided in argv.

        Returns:
            A dict structure that contains different analyzer options.
        """
        # First call the main parse routine
        p = self.parser.parse_args(argv)

        # Then extract base options
        opts = self.base.parse_opts(p)

        # Add extensions
        opts['threshold'] = p.threshold
        opts['whitelist'] = p.whitelist
        opts['blacklist'] = p.blacklist
        if p.rvdb:
            opts['rvdb'] = p.rvdb
        else:
            opts['rvdb'] = None

        if p.reportfile:
            opts['reportfile'] = p.reportfile
        else:
            opts['reportfile'] = None

        if p.showgraph:
            opts['showgraph'] = p.showgraph
        else:
            opts['showgraph'] = None

        if p.graphfile:
            opts['graphfile'] = p.graphfile
        else:
            opts['graphfile'] = None

        if p.clustergraph:
            opts['clustergraph'] = p.clustergraph
        else:
            opts['clustergraph'] = None

        if p.clusterplot:
            opts['clusterplot'] = p.clusterplot
        else:
            opts['clusterplot'] = None

        return opts

    def get_help(self):
        """Return the formatted help text.

        Returns:
            Str value containing formatted help text.
        """
        return self.parser.format_help()
