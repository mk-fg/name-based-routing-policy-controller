# Name-based Routing Policy Controller (nbrpc)

A tool for monitoring service availability and policy-routing around
the issues deliberately and selectively created on either side, aka censorshit.

> "The Net interprets censorship as damage and routes around it."
> -- John Gilmore

"The Net" won't do it all by itself however, hence the tool here.

Especially useful these days, when local state, everyone around,
and the rest of the world hate you, working together to cut you off
from the interwebs, if you happen to live in a wrong place at a wrong time,
but it does seem to be a global trend too.

Table of Contents

- [More Description](#hdr-more_description)
- [Routing policy decision-making logic](#hdr-routing_policy_decision-making_logic)
- [Setup and usage](#hdr-setup_and_usage)
- [Check list file format]
- [Setup example with linux policy routing]
- [Related links, tips, info and trivia]

[Check list file format]: #hdr-check_list_file_format
[Setup example with linux policy routing]:
  #hdr-setup_example_with_linux_policy_routing
[Related links, tips, info and trivia]:
  #hdr-related_links__tips__info_and_trivia

Repository URLs:

- https://github.com/mk-fg/name-based-routing-policy-controller
- https://codeberg.org/mk-fg/name-based-routing-policy-controller
- https://fraggod.net/code/git/name-based-routing-policy-controller


<a name=hdr-more_description></a>
## More Description

It is a script for monitoring DNS names for whether services on their IPs
are not accessible through direct connections and configuring linux (probably)
policy routing to use alternative paths to those hosts.

Purpose is to work around access issues to often-used known-in-advance
websites/services that get blocked on either side of the route to them
(by either state censorship or geo-blocking), without running all traffic
through tunnels unnecessarily, and without manually configuring proxies/tunnels
in specific apps.

List of handled hostnames is supposed to be maintained manually,
with script issuing notifications when those don't need to be on the list anymore,
i.e. when direct route to those works, which requires script itself to be excluded
from the routing policy that it sets up.

Actual routing configuration should be changed by other hook scripts, likely
running with more access to update [nftables sets], [ip-route tables],
[ip-rules] or somesuch - see examples below for more info.

It'd also make sense to use reasonably secure/private DNS resolution
alongside this tool - see [DNS Privacy project] for more info on that.

Scripts here are not intended to do any tricks to fool DPI, discard RST
packets or otherwise work around specific censorshit types and implementations,
just route stuff around whatever, whereever or by-whomever it is.

If you don't want to run traffic over tunnels, and/or trying to bypass specific
national firewalls, lookup tools like [XTLS Xray/REALITY], [GreenTunnel],
[GoodbyeDPI], [PowerTunnel], [NaïveProxy], [zapret], [xt_wgobfs] instead.

This script also will not work for hiding or obfuscating the fact of
accessing something (which is a very complex and different subject),
I'd recommend using [Tor Project] and similar privacy toolkits instead,
with all traffic wrapped indiscriminately (access info leaks in many
ways - traffic patterns, third-party page content, OCSP packets, etc)
and a dedicated privacy-focused clients/OS as well (like [Tails] and [Tor Browser]).

[nftables sets]: https://wiki.nftables.org/wiki-nftables/index.php/Sets
[ip-route tables]: https://man.archlinux.org/man/ip-route.8.en
[ip-rules]: https://man.archlinux.org/man/ip-rule.8.en
[DNS Privacy project]: https://dnsprivacy.org/
[XTLS Xray/REALITY]: https://github.com/XTLS
[GreenTunnel]: https://github.com/SadeghHayeri/GreenTunnel
[GoodbyeDPI]: https://github.com/ValdikSS/GoodbyeDPI
[PowerTunnel]: https://github.com/krlvm/PowerTunnel
[NaïveProxy]: https://github.com/klzgrad/naiveproxy
[zapret]: https://github.com/bol-van/zapret
[xt_wgobfs]: https://github.com/infinet/xt_wgobfs
[Tor Project]: https://www.torproject.org/
[Tails]: https://tails.boum.org/
[Tor Browser]: https://www.torproject.org/download/


<a name=hdr-routing_policy_decision-making_logic></a>
## Routing policy decision-making logic

General idea and some less-obvious quirks of availability-checking
done by the script are listed below.


- Whole tool can be decomposed into following parts:

    - Local sqlite db file, storing all service availability and checks info.

    - Service availability checking backend.

        Selects/rate-limits/schedules which checks to run and runs them,
        where each check can be split in two parts:

        - DNS resolution to an ever-changing list of cloud IPs.

        - Probing individual DNS name + IPv4/IPv6 address combinations via curl or such.

    - Actions on availability changes.

        - Applying re-routing workarounds "policy", via separate script,
          which might need additional privileges to e.g. manipulate host's nftables.

        - Applying DNS workarounds/overrides.

    - Separate glue script(s) updating routing policies
      or DNS zones, called from actions above.

    It's useful to think about these concepts/components separately like that,
    to talk about them in relative isolation, as is mostly done below.


- DNS parts can be tricky.

    Service DNS names are expected to resolve to multiple IPs, which change anytime,
    as CDNs hand them out randomly depending on time, place, load, phase of the
    moon or whatever.

    This introduces a problem that apps can use different IP from checked ones,
    unless either some DNS hack is introduced, or checks are run sufficiently often
    and remember/re-route old IPs if those get handed-out in a round-robin fashion.

    So, DNS resolution for a particular site/service can be handled in following ways:

    - Not altered, if its IPs are stable enough, they're checked often enough
      and/or with enough history, or just hitting occasional unchecked/blocked
      one is not a big deal.

    - Limit service to checked/rerouted IPs.

        Safe opposite to above, to have apps use maybe slightly-stale addrs that
        were confirmed to work, one way or another.

    - Limit service to IPs that were checked and confirmed to be working directly,
      maybe even older ones from earlier queries (if host rotates returned IPs).

        Useful for high-traffic or latency-sensitive services, where
        poorly-implemented censorshit laws block random IPs from the pool,
        resulting in stuff occasionally timing-out at random, but tunneling it
        can be less convenient/slow/costly than just dropping these unlucky addrs.

    When some form of DNS override/filtering is in place, script can be used
    with `-Z/--zone-for` option to export records for that at any time,
    selecting strategies from the list above on per-host or per-run basis.

    Option dumps local-zone info to stdout (in [Unbound] resolver format by default),
    filtered by regexp for hostname(s) and any policy modifiers.
    Using larger superset of "all seen" addresses can be useful to schedule
    these updates less often, and not bother tracking upstream results exactly.


- Enabling workarounds on failed connection checks can be done in different ways too.

    - Reroute all old-and-current service IPs
      if any/some/all of them are confirmed to be blocked.

        It's useful to have longer grace periods or run alt-route checker here,
        to avoid flapping workarounds on/off whenever services have any common
        temporary issues on any of their endpoints.

    - Same as above, but re-route specific address family (IPv4/IPv6),
      when IPs in there are detected to be inaccessible.

        This takes into account the fact that censorship is often simple,
        and applies to a list of some IPv4 ranges only, as well as the fact
        that IPv6 often gets broken on its own, so it's useful to treat these
        AFs and their specific issues separately.

        Idea is kinda similar to [Happy Eyeballs algorithm], which is widely used
        when establishing connections with both IPv4/IPv6 options available.

    - Reroute/tunnel only blocked-somewhere IPs that don't pass the checks.

        Can be a smart way to do it with larger CDNs or an even dumber censorshit.

    - Forego routing workarounds entirely in favor of some other solution.
      DNS workarounds (filtering-out blocked addrs) or notifications
      for something manual, for example.

    These strategies can be toggled via global `-p/--check-list-default-policy`
    option and set on a per-service/host basis to handle different things differently.

    For small or known-blocked sites it can be easier to have broad "reroute it all"
    policies, but might not be worth clogging the tunnel with all cloudflare, youtube
    or twitch.tv video traffic at all, and only work around issues there on the DNS level,
    if possible.


- Checking "hostname + address" combination tends to be special for each host.

    Default checks ("https") are not just ICMP pings or TCP connections,
    but a curl page fetch, expecting specific http response codes,
    to catch whatever mid-https RST packets (often for downgrade to ISP's http
    blacklist page) and hijacking with bogus certs, which seem to be common for
    censorship-type filtering situation.

    It's useful to check and customize which response code is expected by using
    e.g. "api.twitter.com=404" or query specific URL paths that return specific
    http results, e.g. "somesite.com:https/api/v5=400", especially if generic
    redirect responses are known to indicate access failure (leading to either
    censorshit or a F-U page).


- Good service availability check for specific address consists of two parts -
  checking it via direct connection, and checking it via alternate route that's
  supposed to be used as a workaround.

    This is done so that checks don't just track general upstream up/down status,
    but only mark things as needing workaround when it legitimately works that way,
    unlike direct connection.


- State of hosts in db only gets changed after a grace period(s), to avoid
  flapping between routes needlessly during whatever temporary issues, like
  maybe service being down in one geo-region or on some frontend IPs for a bit.

    Both directions have different timeouts and transition rules - e.g. flipping
    to workaround state is faster than back to direct connections by default,
    and is done through intermediate "failing" state, with possible alt-route
    checks in-between, to stall the transition if endpoint seem to be down from
    both network perspectives.

    All timeouts, intervals and delays are listed in `-h/--help` output and are
    easily configurable.


- Non-global/public addrs (as in iana-ipv4/ipv6-special-registry) are ignored in
  getaddrinfo() results for all intents and purposes, to avoid hosts assigning
  junk IPs messing with any checks or local routing.

[Happy Eyeballs algorithm]: https://datatracker.ietf.org/doc/html/rfc6555


<a name=hdr-setup_and_usage></a>
## Setup and usage

Main [nbrpc.py] is just one Python (3.9+) script that only needs common [curl]
tool for its http(s) checks.
Grab and drop it into any path, run with `-h/--help` option to get started.
`--debug` option there can be used to get more insight into what script is doing.

Main script runs availability checks, but doesn't do anything beyond that by default.

It expects a list of services/endpoints to check with `-f/--check-list-file`
option, format for which is documented in [Check list file format] section below.

Hook scripts/commands can be run directly with `--policy-*-cmd` options,
to control whatever system used for connection workarounds, or send this data
to unix socket (`-s/--policy-socket` option), e.g. to something more privileged
outside its sandbox that can tweak the firewall.

[nbrpc-policy-cmd.py] and [nbrpc-policy-nft.py] scripts in the repo can be used
instead of direct hooks with `-s/--policy-socket` option, and as an example
of handling such socket interactions.

[nbrpc.service] and other \*.service files can be used to setup the script(s)
to run with systemd, though make sure to tweak Exec-lines and any other paths
in there first.

`-P/--print-state` can be used to check on all host and address states anytime.

Once that works, additional instance of the script can be added to run in
mostly same way, but with following two diffs:

- `-F/--failing-checks` option added, and maybe interval tweaks.
- Firewall/routing setup to send all traffic of that second instance through
  whatever workaround route/tunnel that is supposed to be used.

See info on that option for more details, but gist is that running such instance
can help to detect prolonged global service outages and avoid marking hosts as
blocked if they just don't work anywhere due to that.
"host-na-state" grace-interval should prevent changing state on brief outages without this.

Also see below for an extended OS routing integration example.

[nbrpc.py]: nbrpc.py
[nbrpc-policy-cmd.py]: nbrpc-policy-cmd.py
[nbrpc-policy-nft.py]: nbrpc-policy-nft.py
[nbrpc.service]: nbrpc.service


<a name=hdr-check_list_file_format></a>
## Check list file format

Should be a space/newline-separated list of hostnames to check.

Each spec can be more than just hostname: `hostname[>policy][:check][=expected-result]`

- `hostname` - hostname or address to use with getaddrinfo() for each check.

    It almost always makes sense to only use names for http(s) checks, as sites
    tend to change IPs, and names are required for https, SNI and proper vhost
    responses anyway.

- `check` - type of check to run.

    Currently supported checks: `https`, `http`, `dns`. Default: `https`.

    http/https checks can also have a pre-encoded URL path included, e.g.
    `https/url/path...`, to query that for more useful response status code.
    If there's `=` in URL path, replace/escape it with `==`.

    "dns" check is a no-op to track IPs for zone-files output or other purposes.

- `expected-result` - for http(s) checks - response code(s) to treat as an OK result,
  with anything else considered a failure, separated by slash ("/"). Default is 200/301/302.

    Special `na` value will always return failure for any check without running it.

- `policy` - how to combine conflicting check results for different host addresses.

    This value should look like `reroute-policy.dns-flags`, where both
    dot-separated parts are optional.

    `reroute-policy` can be one of the following values:

    - `af-any` - host considered ok if all addrs on either IPv4 or IPv6 address family (AF) are okay.
    - `af-all` - any blocked addr on any AF = host considered N/A.
    - `af-pick` - reroute all addrs of AF(s) that have any of them blocked.
    - `pick` - reroute individual addrs that appear to be blocked, instead of per-host/AF policy.
    - `noroute` - always return same "ok" for routing policy purposes.

    `dns-flags` part is a combination of any number of one-char DNS-filtering
    flags from the following list:

    - `4` - only resolve and use/check IPv4 A records/addrs for host.
    - `6` - only resolve/use/check IPv6 AAAA addresses.
    - `D` - print only records for directly-accessible addrs of this host.
    - `N` - only print records for inaccessible/rerouted addrs.
    - `L` - print only latest records IPs from last getaddrinfo() for host, not any earlier ones.
    - `1` - only take addrs from last getaddrinfo() into account for updating host state.
    - `R` - always print records in a random (shuffled) order.

    Where "print" flags are only relevant when using `-Z/--zone-for` option.

    Any combination of these should work - for example `pick.6`, `LD4`,
    `af-all`, `af-pick.NL` - but using some DNS flags like `46` together
    makes them negate each other.

    Default value is `af-all`.
    Can be changed via `-p/--check-list-default-policy` script option.

Empty lines are fine, anything after # to the end of the line is ignored as comment.

Simple Example:

```
## Twitter and some of its relevant subdomains
twitter.com
abs.twimg.com=400 api.twitter.com=404 # some endpoints don't return 200

## Random other check-type examples
oldsite.com:http
fickle-site.net=200/503
httpbin.org:https/status/478=478

## Policy examples
www.wikipedia.org>pick.RL
abcdefg.cloudfront.net>LD:https/api=400

## Always route-around Lets-Encrypt OCSP requests for more privacy/reliability
# https://letsencrypt.org/docs/lencr.org/
ocsp.int-x3.letsencrypt.org=na r3.o.lencr.org=na
```

These config files can be missing, created, removed or changed on the fly,
with their mtimes probed on every check interval, and contents reloaded as needed.

At least one `-f/--check-list-file` option is required, even with nx path.


<a name=hdr-setup_example_with_linux_policy_routing></a>
## Setup example with linux policy routing

Relatively simple way to get this tool to control network is to have it run
on some linux router box and tweak its routing logic directly for affected IPs,
routing traffic to those through whatever tunnel, for example.

This is generally called "Policy Routing", and can be implemented in a couple
different ways, more obvious of which are:

- Add custom routes to each address that should be indirectly accessible
  to the main routing table.

    E.g. `ip ro add 216.58.211.14 via 10.10.0.1 dev mytun`, with 10.10.0.1 being
    a custom tunnel gateway IP on the other end.

    Dead-simple, but can be somewhat messy to manage.

    [ip route] can group/match routes by e.g. "realm" tag, so that they can be
    nuked and replaced all together to sync with desired state.

    It also has `--json` option, which can help managing these from scripts,
    but it's still a suboptimal mess for this purpose.

- Add default tunnel gateway to a separate routing table,
  and match/send connections to that using linux [ip rules] table:

    ```
    ip ro add default via 10.10.0.1 dev mytun table vpn
    ip ru add to 216.58.211.14 lookup vpn
    ```

    (table "vpn" can be either defined in `/etc/iproute2/rt_tables` or referred
    to by numeric id instead)

    Unlike with using default routing table above, this gives more flexibility wrt
    controlling how indirect traffic is routed - separate table can be tweaked
    anytime, without needing to flush and replace every rule for each IP-addr.

    It's still sequential rule-matching, lots of noise (moved from ip-route to
    ip-rule table), and messy partial updates.

- Match and mark packets using powerful firewall capabilities (old iptables,
  nftables or ebtables) and route them through diff tables based on that:

    ```
    ip ro add default via 10.10.0.1 dev mytun table vpn
    ip ru add fwmark 0x123 lookup vpn
    nft add rule inet filter pre iifname mylan ip daddr 216.58.211.14 mark set 0x123
    ```

    It's another layer of indirection, but [nftables] (linux firewall) has proper
    IP sets with atomic updates and replacement to those.

    So that one marking rule can use nftables set - e.g.
    `nft add rule inet filter pre iifname mylan ip daddr @nbrpc mark set 0x123` -
    and those three rules are basically all you ever need for dynamic policy routing.

    Just gotta add/remove IPs in @nbrpc to change routing decisions, all being
    neatly contained in that set, with very efficient packet matching,
    and infinitely flexible too if necessary (i.e. not only by dst-ip, but pretty
    much anything, up to and including running custom BPF code on packets).

    Having decisions made at the firewall level also allows to avoid this routing
    to affect the script itself - "prerouting" hook will already ensure that, as
    it doesn't affect locally-initiated traffic, but with e.g. "route" hook that
    does, something trivial like `skuid nbrpc` can match and skip it by
    user/group or cgroup where it's running under systemd.

[nbrpc-policy-nft.py] script in this repo can be used with that last approach,
can run separately from the main checker script (with [cap_net_admin] to tweak
firewall), replacing specified IPv4/IPv6 address sets on any changes.

General steps for this kind of setup:

- Some kind of external tunnel, for example:

    ```
    ip link add mytun type gre local 12.34.56.78 remote 98.76.54.32
    ip addr add 10.10.0.2/24 dev mytun
    ip addr add fddd::10:2/120 dev mytun
    ip link set mytun up
    ```

    Such GRE tunnel is nice for wrapping any IPv4/IPv6/eth traffic to go between
    two existing IPs, but not secure to go over internet by any means - something
    like [WireGuard] is much better for that (and GRE can go over some pre-existing
    wg link too!).

- Policy routing setup, where something can be flipped for IPs to switch between
  direct/indirect routes:

    ```
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
    ```

    "nbrpc4" and "nbrpc6" nftables sets in this example will have a list of IPs
    that should be routed through "vpn" table and GRE tunnel gateway there,
    add snat/masquerade rules after that as needed.

    "type route" hook will also mark/route host's own traffic for matched IPs
    (outgoing connections from its OS/pids), not just stuff forwarded through it.

    Firewall rules should probably be in nftables.conf file, and have a hook
    sending SIGHUP to nbrpc on reload, to have it re-populate sets there as well,
    while "ip" routes/rules configured in whatever network manager, if any.

    Reverse "skuid" match should be applied to script instance running with
    `-F/--failing-checks`, if it is used, to have all its traffic routed through
    "vpn" table, as opposed to the main instance.

- Something to handle service availability updates from main script
  and update routing policy:

    ```
    cd ~nbrpc
    capsh --caps='cap_net_admin+eip cap_setpcap,cap_setuid,cap_setgid+ep' \
      --keep=1 --user=nbrpc --addamb=cap_net_admin --shell=/usr/bin/python -- \
      ./nbrpc-policy-nft.py -s nft.sock -4 :nbrpc4 -6 :nbrpc6 -p
    ```

    Long capsh command (shipped with libcap) runs nbrpc-policy-nft.py with
    [cap_net_admin] to allow it access to the firewall without full root.
    Same as e.g. `AmbientCapabilities=CAP_NET_ADMIN` with systemd.

- Main nbrpc.py service running checks with its own db:

    ```
    cd ~nbrpc
    su-exec nbrpc ./nbrpc.py --debug -f hosts.txt -Ssx nft.sock
    ```

    Can safely run with some unprivileged uid and/or systemd/lsm sandbox setup,
    only needing to access nft.sock unix socket of something more privileged,
    without starting any fancy sudo/suid things directly.

- Setup tunnel endpoint and forwarding/masquerading on the other side, if missing.

That is to use checked services' status to tweak OS-level routing though,
and failover doesn't have to be done this way - some exception-list can be used
in a browser plugin to direct it to use proxy server(s) for specific IPs,
or something like [Squid] can be configured as a transparent proxy with its own
config of rules, or maybe this routing info can be relayed to a dedicated router
appliance.

Main nbrpc script doesn't care either way - give it a command or socket to feed
state/updates into and it should work.

[curl]: https://curl.se/
[ip route]: https://man.archlinux.org/man/ip-route.8.en
[ip rules]: https://man.archlinux.org/man/ip-rule.8.en
[nftables]: https://nftables.org/
[WireGuard]: https://www.wireguard.com/
[cap_net_admin]: https://man.archlinux.org/man/capabilities.7.en
[Squid]: http://www.squid-cache.org/


<a name=hdr-related_links__tips__info_and_trivia></a>
## Related links, tips, info and trivia

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
    using e.g. `-P/--print-state`, `-u/--update-host` and such options.

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
    with iface names anyway:

    ```
    nft add rule inet filter forward iifname lan oifname mytun cm mark 0x123 accept
    nft add rule inet filter forward iifname mytun oifname lan accept
    nft add rule inet nat postrouting oifname mytun cm mark 0x123 masquerade
    ```

- Tunnels tend to have lower MTU than whatever endpoints might have set on their
  interfaces, so [clamping TCP MSS via nftables] is usually a good idea:

    ```
    nft add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu
    ```

    This can be tested via e.g. `ping -4M do -s $((1500-28)) somehost.net`
    (1500B MTU - 8B ICMP header - 20B IPv4 header) plus the usual tcpdump to see
    MSS on TCP connections and actual packet sizes, and it's quite often not what
    you expect, so always worth checking at least everywhere where tunneling or
    whatever overlay protocols are involved.

- systemd-networkd will clobber routes and rules defined via iproute2 "ip" tools
  from console or some script by default, at somewhat random times.

    `ManageForeignRoutingPolicyRules=no` and `ManageForeignRoutes=no` options
    in networkd.conf can be used to disable that behavior, or routes/rules defined
    via its configuration files properly.

- If some service is hopping between IPs too much, so that nbrpc can't catch-up
  with it, and occasionally-failing connections are annoying, script has
  `-Z/--zone-for` option to export local-zone with only A/AAAA records
  known to it (or some subset - see option description) for regexp-filtered list
  of known/managed hostnames (can be just `-Z.` to dump all of them).

    Output produced there by default can be used with [Unbound]'s (DNS
    resolver/cache daemon) `include:` directive, or with [CoreDNS] "hosts"
    directive (picking \/etc\/hosts file format with `-z hosts` option),
    or parsed/converted for other local resolvers from those.
    Should probably be scheduled via systemd timer
    (with e.g. `StandardOutput=truncate:...` line) or crontab.

    Note that same DNS resolver with zone overrides shouldn't be used for main
    nbrpc script itself, which can be easy to fix by e.g. bind-mounting different
    resolv.conf file (pointing to unrestricted resolver) into its systemd service/container.

- While intended to work around various network disruptions, this stuff can also
  be used in the exact opposite way - to detect when specific endpoints are
  accessible and block them - simply by reading "ok" result in policy-updates as
  undesirable (instead of "na", adding blocking rules), e.g. in a [pihole]-like scenario.

- [test.sh](test.sh) script can be used to easily check or create any oddball
  blocking-over-time scenarios and see how logic of the tool reacts to those,
  coupled with specific configuration or any local code tweaks, and is full of examples.

- ["Dynamic policy routing to work around internet restrictions" blog post]
  with a bit more context and info around this script.


[clamping TCP MSS via nftables]:
  https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers
[Unbound]: https://unbound.docs.nlnetlabs.nl/
[CoreDNS]: https://coredns.io/
[pihole]: https://pi-hole.net/
["Dynamic policy routing to work around internet restrictions" blog post]:
  https://blog.fraggod.net/2022/04/05/dynamic-policy-routing-to-work-around-internet-restrictions.html
