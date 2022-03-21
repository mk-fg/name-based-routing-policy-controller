Name-based Routing Policy Controller (nbrpc)
============================================

A tool for monitoring service availibility and policy-routing around the issues.

  | "The Net interprets censorship as damage and routes around it."
  | -- John Gilmore

"The Net" won't do it all by itself however, hence the tool here.

Especially useful these days, when local state, everyone around you, and
everyone in the world hate your guts, and work together to cut you off from
everything, if you happened to be born in a wrong place at a wrong time.

.. contents::
  :backlinks: none


Description
-----------

Script for monitoring DNS names for whether services on their IPs are not
accessible through direct connections and configuring linux policy routing
for alternative paths to those hosts.

Purpose is to work around access issues to often-used known-in-advance websites
that get blocked on either side of the route to them (by either state censorship
or geo-blocking), without running all traffic through tunnels unnecessarily.

List of handled hosts/names is supposed to be maintained manually,
with script issuing notifications when those don't need to be on the list anymore,
i.e. when direct route to those works, which requires script itself to be excluded
from the routing policy that it sets up.

Both IPv4/IPv6 are supported, names are expected to have multiple IPs,
alternate-routing condition is "any of the IPs of the same family is blocked",
while invalidating it requires direct routes to work for some grace period,
to avoid direct/indirect route flapping.


Installation and usage
----------------------

It's a simple Python (3.9+) script that needs python itself and curl_ tool to work.

| Grab and drop it in any path, and run with ``-h/--help`` option to get started.
| Use ``--debug`` option to get more insight into what script is doing.

.. _curl: https://curl.se/
