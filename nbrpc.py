#!/usr/bin/env python

import itertools as it, operator as op, functools as ft, subprocess as sp
import pathlib as pl, contextlib as cl, collections as cs, ipaddress as ip
import os, sys, re, logging, time, socket, errno, signal


class LogMessage:
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self):
		try: return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt
		except: raise ValueError(self.fmt, self.a, self.k)

class LogStyleAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None): super().__init__(logger, extra or dict())
	def loops(self, msg, *args, **kws): return self.log(logging.LOOPS, msg, *args, **kws)
	def log(self, level, msg, *args, **kws):
		if not self.isEnabledFor(level): return
		log_kws = {} if 'exc_info' not in kws else dict(exc_info=kws.pop('exc_info'))
		msg, kws = self.process(msg, kws)
		self.logger._log(level, LogMessage(msg, args, kws), (), **log_kws)

err_fmt = lambda err: f'[{err.__class__.__name__}] {err}'
get_logger = lambda name='': LogStyleAdapter(
	logging.getLogger(name and 'nbrpc' or f'nbrpc.{name}') )

def td_fmt(td):
	s, ms = divmod(td, 1)
	return f'{s//60:02,.0f}:{s%60:02.0f}.{ms*100:02.0f}'


class NBRPConfig:
	_p = pl.Path(__file__)

	host_files = list()
	db_file = _p.parent / (_p.name.removesuffix('.py') + '.db')
	curl_cmd = 'curl'
	curl_ua = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'

	update_all = False
	update_n = None

	td_host_addrs = 40 * 60 # interval between re-resolving host IPs
	td_addr_state = 15 * 3600 # service availability checks for specific addr
	td_host_ok_state = 41 * 3600 # how long to wait for failures to return

	timeout_host_addr = 28 * 3600 # to "forget" addrs that weren't seen in a while
	timeout_addr_check = 30.0 # for http and socket checks
	timeout_log_td_info = 90.0 # switches slow log_td ops to log.info instead of debug
	timeout_kill = 8.0 # between SIGTERM and SIGKILL

	limit_iter_hosts = 8
	limit_iter_addrs = 5


class NBRPDB:
	_db, _db_schema = None, '''
		create table if not exists host_files (
			path text not null primary key, mtime real not null );

		create table if not exists hosts (
			host_file references host_files on delete cascade,
			host text not null primary key,
			chk text not null default 'https',
			state text, ts_check real not null default 0, ts_update real not null default 0 );
		create index if not exists hosts_ts_check on hosts (ts_check);

		create table if not exists addrs (
			host references hosts on delete cascade,
			addr text not null, state text, ts_seen real not null,
			ts_check real not null default 0, ts_update real not null default 0 );
		create index if not exists addrs_pk on addrs (host, addr);
		create index if not exists addrs_ts_check on addrs (ts_check);'''

	def __init__(self, path, lock_timeout=60, lazy=False):
		import sqlite3
		self._sqlite, self._ts_activity = sqlite3, 0
		self._db_kws = dict( database=path,
			isolation_level='IMMEDIATE', timeout=lock_timeout )
		if not lazy: self._db_init()

	def close(self, inactive_timeout=None):
		if ( inactive_timeout is not None
			and (time.monotonic() - self._ts_activity) < inactive_timeout ): return
		if self._db:
			self._db.close()
			self._db = None
	def __enter__(self): return self
	def __exit__(self, *err): self.close()

	def _db_init(self):
		self._db = self._sqlite.connect(**self._db_kws)
		with self._db_cursor() as c:
			for stmt in self._db_schema.split(';'): c.execute(stmt)

	@cl.contextmanager
	def _db_cursor(self):
		self._ts_activity = time.monotonic()
		if not self._db: self._db_init()
		with self._db as conn, cl.closing(conn.cursor()) as c: yield c

	_hosts_file = cs.namedtuple('Host', 'p mtime hosts')
	def host_map_get(self):
		with self._db_cursor() as c:
			c.execute( 'select path, mtime, host from host_files'
				' left join hosts on path = host_file order by path' )
			return dict(
				(p, self._hosts_file(p, rows[0][1] / 1000, set(r[2] for r in rows if r[2])))
				for p, rows in ( (pl.Path(p), list(rows))
					for p, rows in it.groupby(c.fetchall(), key=op.itemgetter(0)) ) )

	def host_file_update(self, p, mtime, hosts0, hosts1):
		p = str(p)
		with self._db_cursor() as c:
			c.execute('savepoint ins')
			try: c.execute('insert into host_files (path, mtime) values (?, ?)', (p, mtime))
			except self._sqlite.IntegrityError:
				c.execute('rollback to ins')
				c.execute('update host_files set mtime = ? where path = ?', (mtime, p))
				if not c.rowcount: raise LookupError(p)
			c.execute('release ins')
			for h in hosts1:
				c.execute('insert or ignore into hosts (host_file, host) values (?, ?)', (p, h))
			if h_set_del := set(hosts0).difference(hosts1):
				h_set_tpl = ', '.join('?'*len(h_set_del))
				c.execute(f'delete from hosts where host in ({h_set_tpl})', tuple(h_set_del))

	def host_file_cleanup(self, p_iter):
		if not (p_set := set(map(str, p_iter))): return
		with self._db_cursor() as c:
			p_set_tpl = ', '.join('?'*len(p_set))
			c.execute(f'delete from host_files where path in ({p_set_tpl})', p_set)

	def _state_val(self, s):
		if not s or s == 'skipped': return None
		elif s == 'ok': return True
		else: return False

	_host_check = cs.namedtuple('HostCheck', 't host state')
	def host_checks(self, ts_max, n):
		with self._db_cursor() as c:
			c.execute( 'select chk, host, state from hosts'
				' where ts_check <= ? order by ts_check limit ?', (ts_max, n) )
			return list(self._host_check(
				chk, host, self._state_val(s) ) for chk, host, s in c.fetchall())

	def host_update(self, ts, host, addrs=list(), addr_timeout=None):
		with self._db_cursor() as c:
			c.execute('update hosts set ts_check = ? where host = ?', (ts, host))
			for addr in set(ip.ip_address(addr) for addr in addrs):
				addr = addr.compressed
				c.execute( 'insert or ignore into addrs'
					' (host, addr, ts_seen) values (?, ?, ?)', (host, addr, ts) )
				if not c.lastrowid:
					c.execute( 'update addrs set ts_seen = ? where'
						' host = ? and addr = ?', (ts, host, addr) )
					if not c.rowcount: raise LookupError(host, addr)
			if addr_timeout:
				c.execute('delete from addrs where ts_seen < ?', (ts - addr_timeout,))

	_addr_check = cs.namedtuple('AddrCheck', 't host addr state')
	def addr_checks(self, ts_max, n):
		with self._db_cursor() as c:
			c.execute( 'select chk, host, addr, addrs.state'
				' from addrs join hosts using (host) where addrs.ts_check <= ?'
				' order by addrs.ts_check limit ?', (ts_max, n) )
			return list(
				self._addr_check(chk, host, ip.ip_address(addr), self._state_val(s))
				for chk, host, addr, s in c.fetchall() )

	def addr_update(self, ts, host, addr, state0, state1):
		with self._db_cursor() as c:
			if state0 == state1: upd, upd_args = '', list()
			else:
				upd = ', state = ?, ts_update = ?'
				upd_args = 'ok' if state1 is True else (state1 or 'skipped'), ts
			addr = ip.ip_address(addr).compressed
			c.execute( f'update addrs set ts_check = ?{upd}'
				' where host = ? and addr = ?', (ts, *upd_args, host, addr) )
			if not c.rowcount: raise LookupError(host, addr)

	def host_state_sync(self, ts, td_ok_flip, host_iter):
		hs_tpl, changes = ', '.join('?'*len(hs := set(host_iter))), dict()
		with self._db_cursor() as c:
			c.execute( 'select host from addrs'
				f' join hosts using (host) where host in ({hs_tpl})'
				' and (hosts.state is null or hosts.state = ?)'
				' and addrs.state != ? limit 1', (*hs, 'ok', 'ok') )
			for host, in c.fetchall():
				c.execute( 'update hosts set state = ?,'
					' ts_update = ? where host = ?', (st := 'na', ts, host) )
				if c.rowcount: changes[host] = st
				hs.remove(host)
			for host in hs:
				c.execute( 'update hosts set state = ?, ts_update = ?'
					' where host = ? and ts_update < ?', (st := 'ok', ts, host, ts - td_ok_flip) )
				if c.rowcount: changes[host] = st
		return changes


class NBRPC:
	def __init__(self, conf):
		self.conf, self.log = conf, get_logger()
		self.timers = dict()

	def close(self):
		if self.db:
			self.db.close()
			self.db = None
	def __enter__(self):
		self.db = NBRPDB(self.conf.db_file)
		self.host_map = None
		return self
	def __exit__(self, *err): self.close()

	def log_td(self, tid, log_fmt=None, *log_args):
		if not log_fmt:
			self.timers[tid] = time.monotonic()
			return
		td_str = td_fmt(td := time.monotonic() - self.timers[tid])
		if log_fmt is ...: return td_str
		if td < self.conf.timeout_log_td_info:
			self.log.debug(log_fmt, *log_args, td=td_str)
		else: self.log.info(f'[SLOW] {log_fmt}', *log_args, td=td_str)

	def host_map_sync(self, _re_rem=re.compile('#.*')):
		if self.host_map is None: self.host_map = self.db.host_map_get()
		host_files = list(pl.Path(os.path.abspath(p)) for p in self.conf.host_files)
		host_fns = dict.fromkeys(set(self.host_map).union(host_files))
		for n in range(1, 21):
			if n < 20 and len(set(tuple(
				str(p).split(os.sep)[-n:] ) for p in host_fns)) < len(host_fns): continue
			for p in host_fns: host_fns[p] = os.sep.join(str(p).split(os.sep)[-n:])
			break
		for p in host_files:
			try: mtime = p.stat().st_mtime
			except FileNotFoundError: mtime = 0
			if abs( (hf := self.host_map.get( p,
				self.db._hosts_file(p, 0, set()) )).mtime - mtime ) < 0.01: continue
			hosts = set() if not mtime else set(it.chain.from_iterable(
				_re_rem.sub('', line).split() for line in p.read_text().splitlines() ))
			self.db.host_file_update(p, mtime, hf.hosts, hosts)
			self.host_map[p] = self.db._hosts_file(p, mtime, hosts)
			if hf.hosts != hosts:
				self.log.info('Hosts-file update: {} ({:,d} hosts)', host_fns[p], len(hosts))
		host_files_del = set(self.host_map).difference(host_files)
		for p in host_files_del: self.log.info('Hosts-file removed: {}', host_fns[p])
		self.db.host_file_cleanup(host_files_del)

	def run(self):
		while True:
			self.host_map_sync()
			if not (force_n := self.conf.update_n):
				force_n, self.conf.update_all = self.conf.update_all and 2**32, False
			ts, tsm = time.time(), time.monotonic()
			self.run_iter(ts, force_n)
			if self.conf.update_n: break

			## Delay until next iter
			# XXX: time.sleep(delay - (time.monotonic() - tsm))

	def run_iter(self, ts, force_n=None):
		## Resolve/update host addrs
		host_checks = self.db.host_checks(
			(ts - self.conf.td_host_addrs) if not force_n else ts,
			force_n or self.conf.limit_iter_hosts )
		self.log_td('hosts')
		for chk in host_checks:
			if (svc := chk.t).startswith('tcp-'): svc = int(svc[4:])
			elif svc not in ['http', 'https']: raise ValueError(svc)
			self.log_td('gai')
			try:
				addrs = set( a[4][0] for a in socket.getaddrinfo(
					chk.host, svc, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP ))
			except OSError as err:
				addrs = list()
				self.log_td( 'gai', 'Host getaddrinfo: {} {}'
					' [{td}] - {}', chk.host, chk.t, err_fmt(err) )
			else:
				self.log_td( 'gai', 'Host getaddrinfo: {} {}'
					' [addrs={} {td}]', chk.host, chk.t, len(addrs) )
			self.db.host_update( ts, chk.host,
				addrs, addr_timeout=self.conf.timeout_host_addr )
		if host_checks:
			self.log_td( 'hosts', 'Finished host-addrs'
				' update [{td}]: {}', ' '.join(chk.host for chk in host_checks) )

		## Check address availability
		addr_checks = self.db.addr_checks(
			(ts - self.conf.td_addr_state) if not force_n else ts,
			force_n or self.conf.limit_iter_addrs )
		if addr_checks:
			self.log_td('addrs')
			res = self.run_addr_checks(addr_checks)
			n_fail = len(addr_checks) - (n_ok := sum((r is True) for r in res.values()))
			self.log_td( 'addrs',
				'Finished host-addrs check [ok={} fail={} {td}]: {}',
				n_ok, n_fail, ' '.join(chk.addr.compressed for chk in addr_checks) )
			for chk in addr_checks:
				res_str = res.get(chk.addr) or 'skip-fail'
				if res_str is True: res_str = 'OK'
				self.log.debug( 'Host-addr check:'
					' {} [{} {}] - {}', chk.addr.compressed, chk.t, chk.host, res_str )
			for chk in addr_checks:
				self.db.addr_update(ts, chk.host, chk.addr, chk.state, res.get(chk.addr))

		## Check if any host states should be flipped
		state_changes = self.db.host_state_sync( ts,
			self.conf.td_host_ok_state, (chk.host for chk in host_checks) )
		for host, state in state_changes.items():
			self.log.info('Host state updated: {} = {}', host, state)


	def run_addr_checks(self, addr_checks):
		addr_checks_curl, addr_checks_res = dict(), dict()
		for chk in addr_checks:
			if chk.t not in ['http', 'https', 'dns']:
				self.log.warning('Skipping not-implemented check type: {}', chk.t)
			elif chk.t == 'dns': addr_checks_res[chk.addr] = True
			else: addr_checks_curl[chk.addr] = chk
		if not addr_checks_curl: return addr_checks_res

		curl_ports = dict(http=80, https=443)
		curl_to, curl_fmt = self.conf.timeout_addr_check, (
			'%{urlnum} %{response_code} %{time_total}'
			' :: %{exitcode} %{ssl_verify_result} :: %{errormsg}\n' )
		curl = None if not addr_checks_curl else sp.Popen(
			[ self.conf.curl_cmd, '--disable', '--config', '-',
				'--parallel', '--parallel-immediate', '--max-time', str(curl_to) ],
			stdin=sp.PIPE, stdout=sp.PIPE )

		def curl_term(sig=None, frm=None):
			nonlocal curl
			if not curl: return
			if sig:
				td_str = self.log_td('addrs', ...)
				self.log.warning( 'Terminating curl pid'
					' after timeout [{:,.1f}s elapsed={}]', curl_to, td_str )
			try:
				curl.terminate()
				try: curl.wait(self.conf.timeout_kill)
				except sp.TimeoutExpired: curl.kill()
			except OSError as err:
				if err.errno != errno.ESRCH: raise
			finally: curl, proc = None, curl
			proc.wait()

		signal.signal(signal.SIGALRM, curl_term)
		signal.alarm(round(curl_to * 1.5))
		try:
			# Can also check tls via --cacert and --pinnedpubkey <hashes>
			for n, chk in enumerate(addr_checks_curl.values()):
				proto, host, addr, port = chk.t, chk.host, chk.addr.compressed, curl_ports[chk.t]
				if ':' in addr: addr = f'[{addr}]'
				if n: curl.stdin.write(b'next\n')
				curl.stdin.write('\n'.join([ '',
					f'url = "{proto}://{host}:{port}/"',
					f'resolve = {host}:{port}:{addr}', # --connect-to can also be used
					f'user-agent = "{self.conf.curl_ua}"',
					f'connect-timeout = {curl_to}', f'max-time = {curl_to}',
					*'silent disable globoff fail no-keepalive no-sessionid tcp-fastopen'.split(),
					f'write-out = "{curl_fmt}"', 'output = /dev/null', '' ]).encode())
			curl.stdin.flush(); curl.stdin.close()

			addr_idx = list(addr_checks_curl)
			for line_raw in curl.stdout:
				try:
					line = line_raw.decode().strip().split('::', 2)
					n, code, td = line[0].split()
					(chk_err, tls_err), curl_msg = line[1].split(), line[2]
					try: td = td_fmt(float(td))
					except: pass
					chk = addr_checks_curl[addr_idx[int(n)]]
					if chk_err:
						chk_err = f'curl conn-fail [http={code} err={chk_err} tls={tls_err} {td}]: {curl_msg}'
					elif not code.isdigit() or int(code) != 200: chk_err = f'curl http-fail [http={code} {td}]'
					addr_checks_res[chk.addr] = chk_err or True
				except Exception as err:
					self.log.exception('Failed to process curl status line: {}', line)

		finally:
			signal.alarm(0)
			curl_term()
		return addr_checks_res


def main(args=None, conf=None):
	if not conf: conf = NBRPConfig()

	import argparse, textwrap
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawTextHelpFormatter,
		description='Run host resolver, availability checker and routing policy controller.')

	parser.add_argument('-f', '--host-list-file',
		action='append', metavar='path', default=list(),
		help=dd(f'''
			File with a list of hosts (DNS names or IPs) to monitor
				for availability and add alternative routes to, when necessary.
			Hosts can be separated by spaces or newlines.
			Anything from # characters to newline is considered a comment and ignored.
			Can be missing and/or created/updated on-the-fly,
				with changes picked-up after occasional file mtime checks.'''))
	parser.add_argument('-d', '--db', metavar='path', default=conf.db_file.name,
		help='Path to sqlite database used to track host states. Default: %(default)s')
	parser.add_argument('-t', '--addr-check-timeout',
		type=float, metavar='seconds', default=conf.timeout_addr_check,
		help='Timeout on checking address availability. Default: %(default)ss')
	parser.add_argument('-u', '--update-all', action='store_true',
		help='Force-update all host addresses and availability statuses on start.')

	group = parser.add_argument_group('Logging and debug options')
	group.add_argument('-n', '--force-n-checks', type=int, metavar='n',
		help='Run n forced checks for hosts and their addrs and exit, to test stuff.')
	group.add_argument('-q', '--quiet', action='store_true',
		help='Do not log info about updates that normally happen, only bugs and anomalies')
	group.add_argument('--debug', action='store_true', help='Verbose operation mode')

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	if opts.debug: log = logging.DEBUG
	elif opts.quiet: log = logging.WARNING
	else: log = logging.INFO
	logging.basicConfig(format='%(levelname)s :: %(message)s', level=log)
	log = get_logger()

	conf.host_files = list(pl.Path(p) for p in opts.host_list_file)
	if not conf.host_files: parser.error('No host-list files specified')
	conf.db_file = pl.Path(opts.db)
	conf.update_all, conf.update_n = opts.update_all, opts.force_n_checks
	conf.timeout_addr_check = opts.addr_check_timeout
	log.debug('Initializing nbrpc...')
	with NBRPC(conf) as nbrpc:
		log.debug('Starting nbrpc main loop...')
		nbrpc.run()
		log.debug('Finished')

if __name__ == '__main__': sys.exit(main())
