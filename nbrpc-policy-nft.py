#!/usr/bin/env python

import os, sys, errno, re, time, socket, signal, subprocess as sp
import nftables # should be shipped with nftables tool

p_err = ft.partial(print, file=sys.stderr, flush=True)

def update_iter(sock, timeout):
	while True:
		(c, addr), msg = sock.accept(), list()
		try:
			c.settimeout(timeout)
			cr, cw = (c.makefile(m) for m in ['rb', 'wb'])
			for line in cr:
				if not line.strip(): break
				msg.append(line.strip())
			cw.write(b'OK\n'); cw.flush()
		finally: c.close()
		if msg:
			msg.append(b'')
			yield b'\n'.join(msg)

def main(args=None):
	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		usage='%(prog)s [options] -s socket -n nft-set',
		formatter_class=argparse.RawTextHelpFormatter, description=dd('''
			Script to listen-for and push routing policy info to nftables set.
			Intended to use used with -x/--policy-replace-cmd
				and -s/--policy-socket options of the main nbrpc.py script.
			Logs errors to stderr, if any.'''))
	parser.add_argument('-s', '--socket',
		metavar='path', required=True,
		help='Path to unix socket to listen for policy updates on.')
	parser.add_argument('-r', '--recv-timeout',
		type=float, default=10.0, metavar='seconds',
		help='Timeout on receiving policy update from socket. Default: %(default)ss')
	parser.add_argument('-4', '--nft-set4', metavar='set-ok(:set-na)', help=dd('''
		nftables ipv4_addr set name(s), to replace with received routing policy data.
		Can be a single set name to replace for "ok" (directly accessible)
			entries, or two sets for "ok" and "na" entries, separated by colon.'''))
	parser.add_argument('-6', '--nft-set6',
		metavar='set-ok(:set-na)', help='Same as -4/--nft-set4, but for ipv6_addr elements.')
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
		try:
			for policy in update_iter(sock, opts.recv_timeout):
				addrs = dict(
					ok=dict(ipv4_addr=set(), ipv6_addr=set()),
					na=dict(ipv4_addr=set(), ipv6_addr=set()) )
				for line in policy.decode().strip().splitlines():
					st, name, addr, svc = line.split()
					addrs[st]['ipv4_addr' if ':' not in addr else 'ipv6_addr'].add(addr)
				nft_update = dict(nftables=(nft_cmds := list()))
				for sn, st in (opts.nft_set4, 'ipv4_addr'), (opts.nft_set6, 'ipv6_addr'):
					if not sn: continue
					if ':' not in sn: sn += ':'
					nft_cmds.append(dict(flush=dict(set=dict(name=sn))))
					for sn, sv in zip(sn.split(':', 1), ['ok', 'na']):
						if not (sn and addrs[sv][st]): continue
						nft_cmds.append(dict(add=dict(set=dict(
							name=sn, type=st, elem=list(addrs[sv][st]) ))))
				rc, output, error = nft.json_cmd(nft_update)
				if rc:
					p_err(f'ERROR: Failed to update nftables sets ({opts.nft_set4}, {opts.nft_set6})')
					for line in error.strip().splitlines(): p_err(f'ERROR:   {line}')
		finally: os.unlink(opts.socket)

if __name__ == '__main__': sys.exit(main())
