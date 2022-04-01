#!/usr/bin/env python

import os, sys, errno, re, time, socket, signal, subprocess as sp, functools as ft

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
		usage='%(prog)s [options] -s socket -x cmd',
		formatter_class=argparse.RawTextHelpFormatter, description=dd('''
			Script to listen-for and apply routing policy changes sent over
				unix socket by the main nbrpc.py script, by running specified -x/--policy-cmd.
			Logs errors to stderr, if any.'''))
	parser.add_argument('-s', '--socket',
		metavar='path', required=True,
		help='Path to unix socket to listen for policy updates on.')
	parser.add_argument('-r', '--recv-timeout',
		type=float, default=10.0, metavar='seconds',
		help='Timeout on receiving policy update from socket. Default: %(default)ss')
	parser.add_argument('-t', '--cmd-timeout',
		type=float, default=20.0, metavar='seconds',
		help='Timeout on running policy-update command. Default: %(default)ss')
	parser.add_argument('-x', '--policy-cmd',
		metavar='command', required=True, help=dd('''
			Command to add/remove routing policy rules for specific IP address(-es).
			See corresponding options of the main nbrpc.py script for more info.'''))
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

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
				ts0 = time.monotonic()
				try: sp.run(opts.policy_cmd, check=True, timeout=opts.cmd_timeout, input=policy)
				except sp.TimeoutExpired:
					p_err( f'ERROR: timeout running policy-command'
						' [limit={:,.1f} {td}]', k, opts.cmd_timeout, td=time.monotonic() - ts0 )
				except sp.CalledProcessError as err:
					p_err(f'ERROR: policy-command failed [{td}]', k, td=time.monotonic() - ts0)
		finally: os.unlink(opts.socket)

if __name__ == '__main__': sys.exit(main())
