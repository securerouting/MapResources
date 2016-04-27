MapResources Installation
=========================


Dependencies
------------

The MapResources package has the following external dependencies. These
packages must be installed prior to installing the MapResources package.

* pymongo
* pprint
* urllib
* requests
* xmltodict
* pygraphviz
* networkx
* matplotlib
* json2html
* sqlite3
* ipaddress

Some of these python packages may have additional library and system
pacakge dependencies. For example, pygraphviz has a dependency on the
Graphviz package.


Installation
------------

The package can be installed by running the setup.py script as follows::

    $ python setup.py install


MongoDB Setup
-------------

In order to use MongoDB as the persistent data store, follow directions
given at http://docs.mongodb.org/manual/installation/ in order to
install MongoDB. 


Route Views database setup
--------------------------

When trying to compare against route views data the scripts in this
package expect the route views data to be stored in a database that has
the following schema.


* routeadv table

+-------------+-----------------------------------+
| Column      | Type                              | 
+=============+===================================+
| advId       | integer primary key autoincrement |
+-------------+-----------------------------------+
| at          | integer                           |
+-------------+-----------------------------------+
| prefix      | varchar(255)                      |
+-------------+-----------------------------------+
| prefixStart | int                               |
+-------------+-----------------------------------+
| prefixEnd   | int                               |
+-------------+-----------------------------------+
| sourceAddr  | varchar(255)                      |
+-------------+-----------------------------------+
| sourceAS    | integer                           |
+-------------+-----------------------------------+
| originated  | int                               |
+-------------+-----------------------------------+
| nexthop     | varchar(255)                      |
+-------------+-----------------------------------+
| lastAS      | integer                           |
+-------------+-----------------------------------+
| asciiPath   | varchar(4096)                     |
+-------------+-----------------------------------+


* path table

+-------------+-----------------------------------+
| Column      | Type                              |
+=============+===================================+
| pathId      | integer primary key autoincrement |
+-------------+-----------------------------------+
| advId       | integer REFERENCES routeadv(advId)|
+-------------+-----------------------------------+
| fromAS      | integer                           |
+-------------+-----------------------------------+
| toAS        | integer                           |
+-------------+-----------------------------------+
| count       | integer                           |
+-------------+-----------------------------------+

