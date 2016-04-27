
MapResources - A Whois Resource Discovery Tool.
===============================================

There a number of reasons why an organization may wish to build an
inventory of all routing resources (ASNs, network blocks) that it holds.
While much of this information can be found in Whois registries, the
process of building such a list and the maintenance of such a list over
time is often non-trivial. This is because organizations, through
mergers and splits may change in form and composition over time. The
Whois database itself may become stale from not receiving timely
updates, or could simply become fractured enough over time such that no
one person has full knowledge of the organizational routing resources.

Clearly, an automated interface to Whois is required.

ARIN, the RIR for the North America region, offers access to its Whois
database through a RESTful API. While ARIN does not itself provide a
tool to automate Whois access, the RESTful API provides the necessary
building block to implement such capability.  The MapResources package
is an implementation of this capability.

A starting point in the form of a known POC handle, organization
handle, net handle or ASN number is assumed. Using information contained
within the whois object, the MapResources tool identifies other resource
dependencies and  makes further queries through ARIN's RESTful API in
order to find other resources that the organization may hold. The end
result is a report that constitutes a rough resource inventory and a
network graph that depicts how these resources are related to one
another.

The main driver utility program for this package is
map_resources.map_whois.py. The -h option to this script provides more
information on the different options that are available to the user.

Note that even though most interfaces in the map_resources module are
marked as public, they are still in flux and subject to change.

