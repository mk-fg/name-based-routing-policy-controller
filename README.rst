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

List of handled hostnames is supposed to be maintained manually,
with script issuing notifications when those don't need to be on the list anymore,
i.e. when direct route to those works, which requires script itself to be excluded
from the routing policy that it sets up.

Actual routing configuration should be changed by other hook scripts, likely
running with more access to update `nftables sets`_, `ip-route tables`_,
`ip-rules`_ or somesuch - see examples below for more info.

It'd also make sense to use reasonably secure/private DNS resolution
alongside this tool - see `DNS Privacy project`_ for more info on that.

.. _nftables sets: https://wiki.nftables.org/wiki-nftables/index.php/Sets
.. _ip-route tables: https://man.archlinux.org/man/ip-route.8.en
.. _ip-rules: https://man.archlinux.org/man/ip-rule.8.en
.. _DNS Privacy project: https://dnsprivacy.org/


Routing policy decision-making logic
------------------------------------

Some less-obvious quirks of availability-checking done by the script are listed below.

- Service DNS names are expected to have multiple IPs, which change anytime,
  as CDNs hand them out randomly depending on time, place, load, phase of the
  moon or whatever.

  So service/host address-set-to-check is built from all addrs that were seen for
  it during checks within some reasonable timeframe, like a couple days.

  I.e. if currently handed-out IP addr worked, and ones that were during earlier
  checks didn't, doesn't mean that browser or some other app will use same address,
  so that whole "recently seen" superset is checked to determine if host is being
  blocked, not just the latest subset of IPs.

- Both IPv4/IPv6 are supported, and host is considered to be working directly if
  ALL addrs within ONE OF these address families work.

  Idea here is kinda similar to `Happy Eyeballs algorithm`_.

  IPv6 quite often doesn't work for a service with arbitrary connection errors
  (refused, reset, timeout, etc), while IPv4 works perfectly fine, which is normal
  for a lot of sites (as of 2022 at least), so not insisting on IPv6 is fine.

  But IPv4 can fail to work while IPv6 works due to broken filtering too,
  where either blocking is too narrow/static and site works around it by shifting
  its IPv6 constantly or IPv6 AF is just not filtered at all.

  .. _Happy Eyeballs algorithm: https://datatracker.ietf.org/doc/html/rfc6555

- Default checks ("https") are not just ICMP pings or TCP connections,
  but a curl page fetch, expecting specific http response codes,
  to catch whatever mid-https RST packets (often for downgrade to ISP's http
  blacklist page) and hijacking with bogus certs, which seem to be common for
  censorship-type filtering situation.

  It's possible to further customize which response code is expected by using
  e.g. "api.twitter.com=404", where providing domain that returns 200 is tricky
  or default redirect responses are known to indicate failure.

- Service availability check on specific address consists of two parts -
  checking it via direct connection, and checking it via alternate route.

  This is done so that this tool doesn't just track general upstream up/down
  status, but only marks things as needing a workaround when it legitimately
  works, unlike direct connection.

  TODO: not implemented yet, only direct checks are made

- State of the host only changes after a grace period, to avoid flapping between
  routes needlessly during whatever temporary issues, like maybe service being down
  in one geo-region for a bit.

  Both directions have different timeouts - flipping to workaround state is faster
  than back to direct connections, to prioritize working routes over responsiveness.

- These rules/decisions assume a bias towards indirect connection being more
  reliable than direct one, as this is not a generic availability-failover tool,
  but one intended specifically for working around bad restrictions on "native" IPs.

  It's easy to flip the rules around however, by running "native" and "indirect"
  parts of the script with their routing policies reversed, and layer results from
  that on top of direct checks at the firewall level with some basic precedence logic.

- Non-global/public addrs (as in iana-ipv4/ipv6-special-registry) are ignored in
  getaddrinfo() results for all intents and purposes, to avoid hosts assigning
  junk IPs messing with any checks or local routing.


Setup and usage
---------------

Main nbrpc.py_ is just one Python (3.9+) script that only needs common curl_
tool for its http(s) checks.
Grab and drop it into any path, run with ``-h/--help`` option to get started.
``--debug`` option there can be used to get more insight into what script is doing.

Main script runs availability checks, but doesn't do anything beyond that by default.

It expects a list of services/endpoints to check with ``-f/--check-list-file``
option, format for which is documented in `Check list file format`_ section below.

Hook scripts/commands can be run directly with ``--policy-*-cmd`` options,
to control whatever system used for connection workarounds, or send this data
to unix socket (``-s/--policy-socket`` option), e.g. to something more privileged
outside its sandbox that can tweak the firewall.

nbrpc-policy-cmd.py_ and nbrpc-policy-nft.py_ scripts in the repo can be used
instead of direct hooks with ``-s/--policy-socket`` option, and as an example
of handling such socket interactions.

nbrpc.service_ and other \*.service files can be used to setup the script(s)
to run with systemd, though make sure to tweak Exec-lines and any other paths
in there first.

``-P/--print-state`` can be used to check on all host and address states anytime.

Also see below for an extended OS routing integration example.

.. _nbrpc.py: nbrpc.py
.. _nbrpc-policy-cmd.py: nbrpc-policy-cmd.py
.. _nbrpc-policy-nft.py: nbrpc-policy-nft.py
.. _nbrpc.service: nbrpc.service


Check list file format
----------------------

Should be a space/newline-separated list of hostnames to check.

Each spec can be more than just hostname: ``hostname[:check-type][=expected-result]``

- ``hostname`` - hostname or address to use with getaddrinfo() for each check.

  It almost always makes sense to only use names for http(s) checks, as sites
  tend to change IPs, and names are required for https, SNI and proper vhost
  responses anyway.

- ``check-type`` - type of check to run.

  Currently supported checks: ``https``, ``http``, ``dns``. Default: ``https``.

- ``expected-result`` - for http(s) checks - response code(s) to treat as an OK result,
  with anything else considered a failure, separated by slash ("/"). Default is 200/301/302.

Empty lines are fine, anything after # to the end of the line is ignored as comment.

Simple Example::

  ## Twitter and some of its relevant subdomains
  twitter.com
  abs.twimg.com=400 api.twitter.com=404 # some endpoints don't return 200

These config files can be missing, created, removed or changed on the fly,
with their mtimes probed on every check interval, and contents reloaded as needed.

At least one ``-f/--check-list-file`` option is required, even with nx path.


Setup example with linux policy routing
---------------------------------------

Relatively simple way to get this tool to control network is to have it run on
some linux router box and tweak its routing logic directly for affected IPs,
routing traffic to those through whatever tunnel, for example.

This is generally called "Policy Routing", and can be implemented in a couple
different ways, more obvious of which are:

- Add custom routes to each address that should be indirectly accessible to the
  main routing table.

  E.g. ``ip ro add 216.58.211.14 via 10.10.0.1 dev mytun``, with 10.10.0.1 being
  a custom tunnel gateway IP on the other end.

  Dead-simple, but can be somewhat messy to manage.

  `ip route`_ can group/match routes by e.g. "realm" tag, so that they can be
  nuked and replaced all together to sync with desired state.

  It also has ``--json`` option, which can help managing these from scripts,
  but it's still a suboptimal mess for this purpose.

- Add default tunnel gateway to a separate routing table, and match/send
  connections to that using linux `ip rules`_ table::

    ip ro add default via 10.10.0.1 dev mytun table vpn
    ip ru add to 216.58.211.14 lookup vpn

  (table "vpn" can be either defined in ``/etc/iproute2/rt_tables`` or referred
  to by numeric id instead)

  Unlike with using default routing table above, this gives more flexibility wrt
  controlling how indirect traffic is routed - separate table can be tweaked
  anytime, without needing to flush and replace every rule for each IP-addr.

  It's still sequential rule-matching, lots of noise (moved from ip-route to
  ip-rule table), and messy partial updates.

- Match and mark packets using powerful firewall capabilities (old iptables,
  nftables or ebtables) and route them through diff tables based on that::

    ip ro add default via 10.10.0.1 dev mytun table vpn
    ip ru add fwmark 0x123 lookup vpn
    nft add rule inet filter pre iifname mylan ip daddr 216.58.211.14 mark set 0x123

  It's another layer of indirection, but nftables_ (linux firewall) has proper
  IP sets with atomic updates and replacement to those.

  So that one marking rule can use nftables set - e.g. ``nft add rule inet
  filter pre iifname mylan ip daddr @nbrpc mark set 0x123`` - and those three
  rules are basically all you ever need for dynamic policy routing.

  Just gotta add/remove IPs in @nbrpc to change routing decisions, all being
  neatly contained in that set, with very efficient packet matching,
  and infinitely flexible too if necessary (i.e. not only by dst-ip, but pretty
  much anything, up to and including running custom BPF code on packets).

  Having decisions made at the firewall level also allows to avoid this routing
  to affect the script itself - "prerouting" hook will already ensure that, as
  it doesn't affect locally-initiated traffic, but with e.g. "route" hook that
  does, something trivial like ``skuid nbrpc`` can match and skip it by
  user/group or cgroup where it's running under systemd.

nbrpc-policy-nft.py_ script in this repo can be used with that last approach,
can run separately from the main checker script (with cap_net_admin to tweak
firewall), replacing specified IPv4/IPv6 address sets on any changes.

General steps for this kind of setup:

- Some kind of external tunnel, for example::

    ip link add mytun type gre local 12.34.56.78 remote 98.76.54.32
    ip addr add 10.10.0.2/24 dev mytun
    ip addr add fddd::10:2/120 dev mytun
    ip link set mytun up

  Such GRE tunnel is nice for wrapping any IPv4/IPv6/eth traffic to go between
  two existing IPs, but not secure to go over internet by any means - something
  like WireGuard_ is much better for that (and GRE can go over some pre-existing
  wg link too!).

- Policy routing setup, where something can be flipped for IPs to switch between
  direct/indirect routes::

    nft add chain inet filter route '{ type route hook output priority mangle; }'
    nft add chain inet filter pre '{ type filter hook prerouting priority raw; }'
    nft add chain inet filter vpn-mark;

    nft add set inet filter nbrpc4 '{ type ipv4_addr; }'
    nft add set inet filter nbrpc6 '{ type ipv6_addr; }'

    nft add rule inet filter route oifname mywan jump vpn-mark  ## own traffic
    nft add rule inet filter pre iifname mylan jump vpn-mark    ## routed traffic

    ## Exception for nbrpc script itself
    nft add rule inet filter vpn-mark skuid nbrpc ct mark set 0x123 return
    nft add rule inet filter vpn-mark ct mark == 0x123 return   ## icmp/ack/rst after exit

    nft add rule inet filter vpn-mark ip daddr @nbrpc4 mark set 0x123
    nft add rule inet filter vpn-mark ip6 daddr @nbrpc6 mark set 0x123

    ip -4 ro add default via 10.10.0.1 dev mytun table vpn
    ip -4 ru add fwmark 0x123 lookup vpn
    ip -6 ro add default via fddd::10:1 dev mytun table vpn
    ip -6 ru add fwmark 0x123 lookup vpn

  "nbrpc4" and "nbrpc6" nftables sets in this example will have a list of IPs
  that should be routed through "vpn" table and GRE tunnel gateway there,
  add snat/masquerade rules after that as needed.

  "type route" hook will also mark/route host's own traffic for matched IPs
  (outgoing connections from its OS/pids), not just stuff forwarded through it.

  Firewall rules should probably be in nftables.conf file, and have a hook
  sending SIGHUP to nbrpc on reload, to have it re-populate sets there as well.

- Something to handle service availability updates from main script and update
  routing policy::

    cd ~nbrpc
    capsh --caps='cap_net_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep' \
      --keep=1 --user=nbrpc --addamb=cap_net_admin --shell=/usr/bin/python -- \
      ./nbrpc-policy-nft.py -s nft.sock -4 :nbrpc4 -6 :nbrpc6 -p

  Long capsh command (shipped with libcap) runs nbrpc-policy-nft.py with
  cap_net_admin_ to allow it access to the firewall without full root.
  Same as e.g. ``AmbientCapabilities=CAP_NET_ADMIN`` with systemd.

- Main nbrpc.py service running checks with its own db::

    cd ~nbrpc
    su-exec nbrpc ./nbrpc.py --debug -f hosts.txt -Ssx nft.sock

  Can safely run with some unprivileged uid and/or systemd/lsm sandbox setup,
  only needing to access nft.sock unix socket of something more privileged,
  without starting any fancy sudo/suid things directly.

- Setup tunnel endpoint and forwarding/masquerading on the other side, if missing.

That is to use checked services' status to tweak OS-level routing though,
and failover doesn't have to be done this way - some exception-list can be used
in a browser plugin to direct it to use proxy server(s) for specific IPs,
or something like Squid_ can be configured as a transparent proxy with its own
config of rules, or maybe this routing info can be relayed to a dedicated router
appliance.

Main nbrpc script doesn't care either way - give it a command or socket to feed
state/updates into and it should work.

.. _curl: https://curl.se/
.. _ip route: https://man.archlinux.org/man/ip-route.8.en
.. _ip rules: https://man.archlinux.org/man/ip-rule.8.en
.. _nftables: https://nftables.org/
.. _WireGuard: https://www.wireguard.com/
.. _cap_net_admin: https://man.archlinux.org/man/capabilities.7.en
.. _Squid: http://www.squid-cache.org/


Related links, tips, info and trivia
------------------------------------

- Main script keeps all its state in an sqlite db file (using WAL mode),
  isolating all state changes in exclusive db transactions, so should be fine to
  run multiple instances of it with the same source files and db anytime.

  Potential quirks when doing that can be:

  - Changing check types for host(s) while these checks are running might cause
    address and host state to be set based on type/result info from when that
    check was started, which should be fixed by the next run.

  - If this script is used with giant lists/DBs or on a slow host/storage
    (like an old RPi1 with slow SD card under I/O load), db transactions can
    take more than hardcoded sqlite locking timeout (60 seconds), and abort
    with error after that.

  There should be no reason to run concurrent instances of the script normally,
  with only exception being various manual checks and debug-runs,
  using e.g. ``-P/--print-state``, ``-u/--update-host`` and such options.

- Even though examples here have "nft add rule" commands for simplicity,
  it's generally a really bad idea to configure firewall like that - use same
  exact "add rule" commands or rule-lines in table blocks within a single
  nftables.conf file instead.

  Difference is that conf file is processed and applied/rejected atomically,
  so that firewall can't end up in an arbitrary broken state due to some rules
  failing to apply - either everything gets configured as specified, or error
  is signaled and nothing is changed.

- Masquerading traffic going through the tunnel can be done in the usual way,
  via forward+reverse traffic-matching rules in the "forward" hook and
  "masquerade" or "snat" rule applied by the "nat" hook.

  In the setup example above, given that relevant outgoing traffic should
  already be marked for routing, it can be matched by that mark, or combined
  with iface names anyway::

    nft add rule inet filter forward iifname lan oifname mytun cm mark 0x123 accept
    nft add rule inet filter forward iifname mytun oifname lan accept
    nft add rule inet nat postrouting oifname mytun cm mark 0x123 masquerade

- Tunnels tend to have lower MTU than whatever endpoints might have set on their
  interfaces, so `clamping TCP MSS via nftables`_ is usually a good idea::

    nft add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu

  This can be tested via e.g. ``ping -4M do -s $((1500-28)) somehost.net``
  (1500B MTU - 8B ICMP header - 20B IPv4 header) plus the usual tcpdump to see
  MSS on TCP connections and actual packet sizes, and it's quite often not what
  you expect, so always worth checking at least everywhere where tunneling or
  whatever overlay protocols are involved.

  .. _clamping TCP MSS via nftables:
    https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers

- While intended to work around various network disruptions, this stuff can also
  be used in the exact opposite way - to detect when specific endpoints are
  accessible and block them - simply by reading "ok" result in policy-updates as
  undesirable (instead of "na", adding blocking rules), e.g. in a pihole_-like scenario.

  .. _pihole: https://pi-hole.net/

- `"Dynamic policy routing to work around internet restrictions" blog post`_
  with a bit more context and info around this script.

  .. _"Dynamic policy routing to work around internet restrictions" blog post:
    https://blog.fraggod.net/2022/04/05/dynamic-policy-routing-to-work-around-internet-restrictions.html
