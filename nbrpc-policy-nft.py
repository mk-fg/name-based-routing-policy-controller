#!/usr/bin/env python

import os, sys, errno, re, textwrap, socket, signal, functools as ft, datetime as dt
import nftables # should be shipped with libnftables and nft tool

p_err = ft.partial(print, file=sys.stderr, flush=True)

def p_nft_json(o):
	func = p_nft_json
	if not (pf := getattr(func, 'pf', None)):
		import pprint
		func.n, func.pf = 1, ft.partial(pprint.pformat, width=110, compact=True)
	print(f'[ {dt.datetime.now().isoformat(" ", "seconds")} ] -- nftables update {func.n:,d}')
	for line in func.pf(o).splitlines(): print(f'  {line}')
	sys.stdout.flush()
	func.n += 1

def update_iter(sock, timeout):
	while True:
		cr = cw = None
		(c, addr), msg = sock.accept(), list()
		try:
			c.settimeout(timeout)
			cr, cw = (c.makefile(m) for m in ['rb', 'wb'])
			for line in cr:
				if not line.strip(): break
				msg.append(line.strip())
			if msg:
				msg.append(b'')
				ack = yield b'\n'.join(msg)
			else: ack = True
			if ack: cw.write(b'OK\n'); cw.flush()
		finally:
			if cr or cw: cr.close(); cw.close()
			c.close()

def main(args=None):
	import argparse
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		usage='%(prog)s [options] -s socket -n nft-set',
		formatter_class=argparse.RawTextHelpFormatter, description=dd('''
			Script to listen-for and push routing policy info to nftables set.
			Intended to be used with -x/--policy-replace-cmd and
				-s/--policy-socket options of the main nbrpc.py script, to run nftables calls here.
			Do not run it as root though, use capsh (libcap) or
				systemd .service spec to run the script with cap_net_admin.
			Logs errors to stderr, if any.'''))
	parser.add_argument('-s', '--socket',
		metavar='path', required=True,
		help='Path to unix socket to listen for policy updates on.')
	parser.add_argument('-r', '--recv-timeout',
		type=float, default=10.0, metavar='seconds',
		help='Timeout on receiving policy update from socket. Default: %(default)ss')
	parser.add_argument('-4', '--nft-set4', metavar='set-ok:set-na', help=dd('''
		nftables ipv4_addr set name(s), to replace with received routing policy data.
		Can be a single set name to replace for "ok" (directly accessible)
			entries, or two sets for "ok" and "na" entries, separated by a colon.
		Either or both of set names can be empty strings to don't do anything with those IPs.'''))
	parser.add_argument('-6', '--nft-set6',
		metavar='set-ok:set-na', help='Same as -4/--nft-set4, but for ipv6_addr elements.')
	parser.add_argument('-t', '--nft-table', metavar='name',
		default='filter', help='Table where set is defined. Default: %(default)s')
	parser.add_argument('-f', '--nft-family', metavar='name',
		default='inet', help='Family of the specified -t/--nft-table. Default: %(default)s')
	parser.add_argument('-q', '--quiet', action='store_true',
		help='Do not print warnings about address conflicts and such.')
	parser.add_argument('-p', '--nft-print', action='store_true',
		help='Pretty-print all JSON commands being issued to update libnftables to stdout.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	nft = nftables.Nftables()
	nft.set_json_output(True)

	for sig in signal.SIGINT, signal.SIGTERM:
		signal.signal(sig, lambda sig,frm: sys.exit())

	with socket.socket(socket.AF_UNIX) as sock:
		try: sock.bind(opts.socket)
		except OSError as err:
			if err.errno != errno.EADDRINUSE: raise
			os.unlink(opts.socket); sock.bind(opts.socket)
		sock.listen(8)
		stn = dict(ok='na', na='ok')
		try:
			updates = update_iter(sock, opts.recv_timeout)
			policy = next(updates)
			while True:
				addrs = dict(
					ok=dict(ipv4_addr=dict(), ipv6_addr=dict()),
					na=dict(ipv4_addr=dict(), ipv6_addr=dict()) )
				for line in policy.decode().strip().splitlines():
					st, name, addr, svc = line.split()
					af = 'ipv4_addr' if ':' not in addr else 'ipv6_addr'
					addrs_st, addrs_stn = addrs[st][af], addrs[stn[st]][af]
					warn_name = warn_policy = None
					if warn_name := addrs_st.get(addr): warn_policy = 'same'
					if warn_name := addrs_stn.get(addr): warn_policy = 'opposite'
					else: addrs_st[addr] = name
					if warn_name and not opts.quiet:
						p_err( 'WARN: duplicate address'
							f' ({warn_policy} policy) - {addr} [{name} / {warn_name}]' )

				nft_update = dict(nftables=(nft_cmds := list()))
				for sn, st in (opts.nft_set4, 'ipv4_addr'), (opts.nft_set6, 'ipv6_addr'):
					if not sn: continue
					if ':' not in sn: sn += ':'
					for sn, sv in zip(sn.split(':', 1), ['ok', 'na']):
						if not sn: continue
						set_id = dict( name=sn,
							table=opts.nft_table, family=opts.nft_family, type=st )
						nft_cmds.append(dict(flush=dict(set=set_id)))
						if not addrs[sv][st]: continue
						nft_cmds.append(dict(add=dict(set=dict(**set_id, elem=list(addrs[sv][st])))))

				if opts.nft_print: p_nft_json(nft_cmds)
				err, output, err_msg = nft.json_cmd(nft_update)
				if err:
					p_err(f'ERROR: Failed to update nftables sets ({opts.nft_set4}, {opts.nft_set6})')
					for line in err_msg.strip().splitlines():
						if line.strip(): p_err(f'ERROR:   {line}')
				policy = updates.send(not err)
		finally: os.unlink(opts.socket)

if __name__ == '__main__': sys.exit(main())
