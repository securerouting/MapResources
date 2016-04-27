"""This package enables one to query and inspect ARIN whois objects.

This package exports the following classes:

Data Stores:
    - GenericStore: No caching data store (base class)
        - HashStore: Data store with hash backend
        - DBStore: Data store with MongoDB as the backend

Whois Collection Objects:
    - WhoisCollection: Base class
        - POCCollection: Point of Contact Collection
            - URLCollection: URL Collection (Ephemeral Class)
        - OrgCollection: Organization Collection
        - NetCollection: Network resource collection
            - IPCollection: IP address collection (Ephemeral Class)
            - CIDRCollection: CIDR block Collection (Ephemeral Class)
        - ASNCollection: Autonomous System Number Collection

Analysis and reporting:
    - WhoisAnalyzer: Cluster analyzer
    - ResourceReporter: formats cluster information for reporting

CLI Argument Parser:
    - WhoisOptParser: Parse base command line options
    - AnalyzeOptExtension: Parse analyzer specific command line options

RouteViews Interface:
    - RVFetcher: Fetch route view data from local DB
    - RVComparator: Compare whois and route views data
    - RVComparatorRes: Container for RVComparator results
"""
