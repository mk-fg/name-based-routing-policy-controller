Name-based Routing Policy Controller (nbrpc)
============================================

.. contents::
  :backlinks: none


Description
-----------

Script for monitoring DNS names for whether services on their IPs are not
accessible through direct connections and configuring linux policy routing
for alternative paths to those hosts.

Purpose is to work around blocking on either side for often-used websites that
get blocked on either side of that route (state censorship or geo-blocking),
without running all traffic through tunnels unnecessarily.

List of handled hosts/names is supposed to be maintained manually,
with script issuing notifications when those don't need to be on the list anymore,
i.e. when direct route to those works, which requires script itself to be excluded
from the routing policy that it sets up.

Both IPv4/IPv6 are supported, names are expected to have multiple IPs,
alternate-routing condition is "any of the IPs of the same family is blocked",
while invalidating it requires direct routes to work for some grace period,
to avoid flapping.
