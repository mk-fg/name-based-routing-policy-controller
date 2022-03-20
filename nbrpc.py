#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
import pathlib as pl, contextlib as cl, collections as cs, ipaddress as ip
import os, sys, re, logging, time, socket


class LogMessage:
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self): return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt

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


class NBRPConfig:
	_p = pl.Path(__file__)

	host_files = list()
	db_file = _p.parent / (_p.name.removesuffix('.py') + '.db')

	update_all = False
	addr_check_timeout = 30.0 # for http and socket checks
	log_td_info_timeout = 90.0 # switches slow log_td ops to log.info instead of debug
	td_host_addrs = 40 * 60
	td_addr_block = 15 * 3600
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
			try: return c.execute('insert into host_files (path, mtime) values (?, ?)', (p, mtime))
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

	_host_check = cs.namedtuple('HostCheck', 't host state')
	def host_checks(self, ts_max, n):
		with self._db_cursor() as c:
			c.execute( 'select chk, host, state from hosts'
				' where ts_check <= ? order by ts_check limit ?', (ts_max, n) )
			return list(self._host_check(chk, host, state) for chk, host, state in c.fetchall())

	def host_update(self, ts, host, addrs=list()):
		with self._db_cursor() as c:
			c.execute('update hosts set ts_check = ? where host = ?', (ts, host))
			if not (addr_set := set(ip.ip_address(addr) for addr in addrs)): return
			for addr in addr_set:
				c.execute( 'insert or ignore into addrs'
					' (host, addr, ts_seen) values (?, ?, ?)', (host, addr.compressed, ts) )
				if not c.lastrowid:
					c.execute( 'update addrs set ts_seen = ? where'
						' host = ? and addr = ?', (ts, host, addr.compressed) )
					if not c.rowcount: raise LookupError(host, addr.compressed)

	_addr_check = cs.namedtuple('AddrCheck', 't host addr state')
	def addr_checks(self, ts_max, n):
		with self._db_cursor() as c:
			c.execute( 'select chk, host, addr, state from addrs'
				' where ts_check <= ? join hosts on host order by ts_check limit ?', (ts_max, n) )
			return list(
				self._addr_check(chk, host, addr, state)
				for chk, host, addr, state in c.fetchall() )


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
		td = time.monotonic() - self.timers[tid]
		s, ms = divmod(td, 1)
		td_str = f'{s//60:02,.0f}:{s%60:02.0f}.{ms*100:02.0f}'
		if td < self.conf.log_td_info_timeout:
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

			force, self.conf.update_all = self.conf.update_all, False
			ts, tsm = time.time(), time.monotonic()

			## Resolve/update host addrs
			host_checks = self.db.host_checks(
				(ts - self.conf.td_host_addrs) if not force else ts,
				self.conf.limit_iter_hosts if not force else 2**32 )
			self.log_td('hc')
			for chk in host_checks:
				if (svc := chk.t).startswith('tcp-'): svc = int(svc[4:])
				elif svc not in ['http', 'https']: raise ValueError(svc)
				self.log_td('gai')
				try:
					addrs = set( a[4][0] for a in socket.getaddrinfo(
						chk.host, svc, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP ))
				except OSError: addrs = list()
				self.log_td('gai', 'Host getaddrinfo: {} {} [{td}]', chk.host, chk.t)
				self.db.host_update(ts, chk.host, addrs)
			if host_checks:
				self.log_td( 'hc', 'Finished host-addrs'
					' update [{td}]: {}', ' '.join(chk.host for chk in host_checks) )

			break # XXX

			## Check address availability
			# for chk in self.db.addr_checks(
			# 		ts - self.conf.td_addr_block, self.conf.limit_iter_addrs ):

			## Check if host state can be flipped
			# for chk in host_checks:
			# XXX: state=ok + (ts_updated < x or ts_seen < x) for all addrs

			## Delay until next iter
			# XXX: time.sleep(delay - (time.monotonic() - tsm))


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
		type=float, metavar='seconds', default=conf.addr_check_timeout,
		help='Timeout when checking connections to each addr/port. Default: %(default)ss')
	parser.add_argument('-u', '--update-all',
		action='store_true', help='Force-update all host addresses and'
			' availability statuses regardless of last-check timestamps on start.')

	group = parser.add_argument_group('Logging options')
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
	conf.update_all = opts.update_all
	log.debug('Initializing nbrpc...')
	with NBRPC(conf) as nbrpc:
		log.debug('Starting nbrpc main loop...')
		nbrpc.run()
		log.debug('Finished')

if __name__ == '__main__': sys.exit(main())
