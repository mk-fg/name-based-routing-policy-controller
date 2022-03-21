Name-based Routing Policy Controller (nbrpc)
============================================

A tool for monitoring service availibility and policy-routing around the issues.

  | "The Net interprets censorship as damage and routes around it."
  | -- John Gilmore

"The Net" won't do it all by itself however, hence the tool here.

Especially useful these days, when local state, everyone around,
and the rest of the world hate you, working together to cut you off from
the interwebs, if you happen to live in a wrong place at a wrong time.

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

Actual routing should be changed by the scripts, probably run with sudo/doas to
update `nftables sets`_, `ip-route tables`_, `ip-rules`_ or somesuch.

.. _nftables sets: https://wiki.nftables.org/wiki-nftables/index.php/Sets
.. _ip-route tables: https://man.archlinux.org/man/ip-route.8.en
.. _ip-rules: https://man.archlinux.org/man/ip-rule.8.en


Routing policy decision-making logic
------------------------------------

Some less-obvious quirks of availability-checking done by the script are listed below.

- Service DNS names are expected to have multiple IPs, which change anytime,
  as CDNs might hand them out randomly depending on phase of the moon or whatever.

  So service/host address set to check is built from all IPs that were seen for
  it during checks within some reasonable timeframe, like a day or two.

  I.e. if currently handed-out IP addr worked, and ones that were during earlier
  checks didn't, doesn't mean that browser or some other app will use same address,
  so that whole "recently seen" superset is checked to determine if host is being
  blocked, not just the latest subset of IPs.

- Both IPv4/IPv6 are supported, and host is considered to be working directly if
  ALL addrs withing ONE OF these address families work.

  Idea here is kinda similar to `Happy Eyeballs algorithm`_.

  IPv6 quite often doesn't work for a service, with arbitrary connection errors
  (refused, reset, timeout, etc), while IPv4 is perfectly fine, which is normal
  for a lot of sites (as of 2022 at least), so not insisting on IPv6 working is fine.

  But IPv4 can fail to work while IPv6 works due to broken filtering too,
  where either blocking is too narrow/static and site works around it by shifting
  its IPv6 constantly or IPv6 AF is just not filtered at all.

  .. _Happy Eyeballs algorithm: https://datatracker.ietf.org/doc/html/rfc6555

- Service availability check on specific address consists of two parts -
  checking it via direct connection, and checking it via alternate route.

  This is done so that this tool doesn't just track general upstream up/down
  status, but only marks things as needing a workaround when it legitimately
  works, unlike direct connection.

  TODO: not implemented yet, only direct checks are made

- State of the host only changes after a grace period, to avoid flapping between
  routes needlessly for whatever temporary issues, like maybe service being down
  in one geo-region.

  Both directions have different timeouts - flipping to workaround state is
  faster than back to direct connections, to have things work a bit more smoothly.

- These rules/decisions assume a bias towards indirect connection being more
  reliable than direct one, as this is not a generic availability-failover tool,
  but one intended specifically for working around bad restrictions on "native" IPs.

  It's easy to flip the rules around however, by running "native" and "indirect"
  parts of the script with their routing policies reversed, and layer results from
  that on top of direct checks at the firewall level with some simple precedence logic.


Installation and usage
----------------------

It's a simple Python (3.9+) script that needs python itself and curl_ tool to work.

| Grab and drop it in any path, and run with ``-h/--help`` option to get started.
| Use ``--debug`` option to get more insight into what script is doing.
|

TODO: example on how to use policy routing with nftables sets/marks here

.. _curl: https://curl.se/
