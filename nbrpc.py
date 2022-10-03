#!/usr/bin/env python

import itertools as it, operator as op, functools as ft, subprocess as sp
import pathlib as pl, contextlib as cl, collections as cs, ipaddress as ip, datetime as dt
import os, sys, re, logging, time, socket, random, signal, textwrap, zoneinfo


class LogMessage:
	def __init__(self, fmt, a, k): self.fmt, self.a, self.k = fmt, a, k
	def __str__(self):
		try: return self.fmt.format(*self.a, **self.k) if self.a or self.k else self.fmt
		except: raise ValueError(self.fmt, self.a, self.k)

class LogStyleAdapter(logging.LoggerAdapter):
	def __init__(self, logger, extra=None): super().__init__(logger, extra or dict())
	def log(self, level, msg, *args, **kws):
		if not self.isEnabledFor(level): return
		log_kws = {} if 'exc_info' not in kws else dict(exc_info=kws.pop('exc_info'))
		msg, kws = self.process(msg, kws)
		self.logger._log(level, LogMessage(msg, args, kws), (), **log_kws)

err_fmt = lambda err: f'[{err.__class__.__name__}] {err}'
get_logger = lambda name='': LogStyleAdapter(
	logging.getLogger(name and 'nbrpc' or f'nbrpc.{name}') )
log = get_logger('TMP') # for noisy temp-debug stuff
p_err = ft.partial(print, file=sys.stderr)

def td_fmt(td):
	s, ms = divmod(td, 1)
	v = f'{s//60:02,.0f}:{s%60:02.0f}'
	if s < 10 and ms > 0.001: v += f'.{ms*100:02.0f}'
	return v

def ts_fmt(ts):
	if tz := os.environ.get('NBRPC_TEST_TZ', os.environ.get('TZ')):
		tz = zoneinfo.ZoneInfo(tz)
	return dt.datetime.fromtimestamp(ts, tz or None).strftime('%Y-%m-%d.%H:%M')

def ts_now():
	if ts := os.environ.get('NBRPC_TEST_TS'): return float(ts) + int(1e9)
	return time.time()


class NBRPConfig:
	_p = pl.Path(__file__)

	host_files, host_policy_default = list(), None
	db_file = pl.Path(_p.name.removesuffix('.py') + '.db')
	db_debug, db_lock_timeout = False, 60
	curl_cmd = 'curl'
	curl_ua = 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
	policy_update_cmd = policy_replace_cmd = policy_socket = None
	fake_results = curl_cmd_debug = None

	update_all = update_sync = False
	update_n = update_host = None

	td_checks = 4 * 60 # interval between running any kind of checks
	td_host_addrs = 7 * 60 # between re-resolving host IPs
	td_addr_state = 15 * 3600 # service availability checks for specific addrs
	td_host_ok_state = 41 * 3600 # how long to wait resetting failures back to ok
	td_host_na_state = 10 * 3600 # grace period to wait for host to maybe come back up

	timeout_host_addr = 12 * 24 * 3600 # to "forget" addrs that weren't seen in a while
	timeout_addr_check = 30.0 # for http and socket checks
	timeout_log_td_info = 90.0 # switches slow log_td ops to log.info instead of debug
	timeout_kill = 8.0 # between SIGTERM and SIGKILL
	timeout_policy_cmd = 30.0 # for running policy-update/replace commands

	limit_iter_hosts = 9 # max hosts to getaddrinfo() on one iteration
	limit_iter_addrs = 32 # limit on addrs to check in one iteration
	limit_addrs_per_host = 18 # max last-seen IPs to track for each hostname


### Parsers and structs for translating check-list strings

host_file = cs.namedtuple('HostsFile', 'p mtime hosts')
host_info = cs.namedtuple('HostInfo', 'host chk policy') # strings for db
host_policy = cs.namedtuple( 'HostPolicy',
	'af_any af_all af_pick pick noroute'
	' dns_af dns_st dns_last dns_last_chk dns_shuf' )
host_check = cs.namedtuple('Check', 's ext res svc')

def chk_parse(spec) -> host_info:
	if ':' in spec: host, chk = spec.split(':', 1)
	elif '=' in spec:
		host, chk = spec.split('=', 1)
		chk = f'https={chk}'
	else: host, chk = spec, 'https'
	host, policy = host.split('>', 1) if '>' in host else (host, None)
	return host_info(host, chk, policy)

def chk_tuple(chk) -> host_check:
	chk, svc = chk.replace('==', '\ue578'), 0
	if '=' in chk: chk, res = chk.split('=', 1)
	else: res = None
	s = chk = chk.replace('\ue578', '=')
	if m := re.search(r'^(https?)(/.*)?$', chk):
		s = svc = m.group(1); chk = m.group(2)
	return host_check(s, chk, res, svc)

def chk_policy(spec) -> host_policy:
	if not spec: return host_policy(True, *[False]*4, 0, None, *[False]*3)
	if '.' in spec: route, dns = spec.split('.', 1)
	elif not set(spec).difference('46DNL1R'): route, dns = 'af_any', spec
	else: route, dns = spec, ''
	v4, v6, ok, na, last_chk, last_print, shuf = (k in dns for k in '46DNL1R')
	dns_af = [socket.AF_INET, socket.AF_INET6][v6] if v4^v6 else 0
	try: route = host_policy._fields.index(route.lower().replace('-', '_'))
	except ValueError: raise LookupError(f'Unrecognized reroute-policy: {route!r}')
	return host_policy(*it.chain( (n == route for n in range(5)),
		[dns_af, ok if ok^na else None, last_chk, last_print, shuf] ))


### Rerouting policy logic

def policy_host_state(p, sas4_old, sas6_old, sas4, sas6):
	'Translates per-AF address tri-states to True/False/None host state.'
	if not p.dns_last_chk: sas4.update(sas4_old); sas6.update(sas6_old)
	sa = None
	if p.af_any:
		for saf in sas4, sas6:
			if False in saf: sa = False
			elif True in saf: sa = True; break # any AF all-good = host all-good
	elif p.af_all or p.af_pick:
		for saf in sas4, sas6:
			if False in saf: sa = False; break # any AF not all-good = na state
			elif True in saf: sa = True
	elif p.pick or p.noroute:
		# "Pick" policies only use per-host state for logging/clarity
		sas = sas4 | sas6
		if p.noroute and sas: sa = True
		if p.pick: sa = False not in sas # any blocked = na
	else: raise ValueError(f'Unknown routing policy value: {p}')
	return sa

def policy_host_updates(hosts, addr_checks):
	'Returns host-addrs to pick for updates, with no addrs = all addrs for host.'
	host_updates = cs.defaultdict(set)
	for h in hosts: host_updates[h] = set() # timed updates
	for chk in addr_checks:
		if chk.p.pick or chk.p.noroute: host_updates[chk.host].add(chk.addr)
		elif not chk.p.dns_last_chk or chk.addr_last:
			if chk.p.af_pick:
				if chk.host not in hosts and chk.host_st is True: # all-ok -> all-ok
					if chk.state is None: host_updates[chk.host].add(chk.addr) # new addr
				else: host_updates[chk.host].clear() # cal flip all addr states w/o host state changes
			elif chk.host not in hosts and chk.state is None:
				host_updates[chk.host].add(chk.addr) # new addr
			# XXX: addr-rules are never cleaned-up by policy updates - maybe fix that
	return dict(host_updates)

policy_info = cs.namedtuple('PolicyInfo', 'host state policy chk addr_sts')
def policy_dump(pis):
	lines = list()
	for pi in pis:
		if pi.policy.af_any or pi.policy.af_all:
			addr_sts = dict((a, pi.state) for a in pi.addr_sts)
		elif pi.policy.noroute:
			addr_sts = dict((a, True) for a in pi.addr_sts)
		elif pi.policy.af_pick:
			if pi.state: addr_sts = dict((a, True) for a in pi.addr_sts) # host=ok grace period
			else:
				afs = set(a.version for a, ast in pi.addr_sts.items() if ast is False)
				addr_sts = dict((a, a.version not in afs) for a in pi.addr_sts)
		elif pi.policy.pick:
			addr_sts = dict( (a, ast) for a, ast
				in pi.addr_sts.items() if ast is not None )
		lines.extend( f'{ast} {pi.host} {addr} {pi.chk}\n' for addr, ast in
			sorted((a.compressed, ast and 'ok' or 'na') for a, ast in addr_sts.items()) )
	return ''.join(lines).encode()


### DB ORM layer

class NBRPDB:
	_db = _tx = None
	_db_schema = [ # initial schema + migrations, tracked via pragma user_version
		'''create table if not exists host_files (
				path text not null primary key, mtime real not null );

			create table if not exists hosts (
				host_file references host_files on delete cascade,
				host text not null primary key, chk text not null default 'https',
				state text, ts_check real not null default 0, ts_update real not null default 0 );
			create index if not exists hosts_ts_check on hosts (ts_check);

			create table if not exists addrs (
				host references hosts on delete cascade,
				addr text not null, state text, ts_seen real not null,
				ts_check real not null default 0, ts_update real not null default 0 );
			create unique index if not exists addrs_pk on addrs (host, addr);
			create index if not exists addrs_ts_check on addrs (ts_check);''',

		# ts_check_failing is same as ts_check, but for spacing-out alt-route checks
		'''alter table addrs add column ts_check_failing real not null default 0;
			create index if not exists addrs_ts_check_failing on addrs (ts_check_failing);''',
		# ts_down >= ts_update marks addr as non-existant for host-state purposes,
		#  which alt-route checks set for state=na ones, when it looks down on both sides
		'alter table addrs add column ts_down real not null default 0;',
		# policy string for dns queries and processing check results
		'alter table hosts add column policy text null;' ]

	def __init__( self, path,
			policy_default=None, lock_timeout=60, lazy=False, debug=False ):
		import sqlite3
		self._sqlite, self._ts_activity, self.debug = sqlite3, 0, debug
		self._chk_policy = lambda p: chk_policy(p) if p else policy_default
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
		with self() as c:
			c.execute('pragma journal_mode=wal')
			c.execute('pragma user_version')
			if (sv := c.fetchall()[0][0]) == (sv_chk := len(self._db_schema)): return
			elif sv > sv_chk:
				raise RuntimeError('DB schema [{sv}] newer than the script [{sv_chk}]')
			for sv, sql in enumerate(self._db_schema[sv:], sv+1):
				for st in sql.split(';'): c.execute(st)
			c.execute(f'pragma user_version = {sv}')

	@cl.contextmanager
	def __call__(self):
		self._ts_activity = time.monotonic()
		if not self._db: self._db_init()
		if self._tx:
			with cl.closing(self._tx.cursor()) as c: yield c
		else:
			with self._db as conn, cl.closing(conn.cursor()) as c: yield c

	def _upd_check(self, c, *lookup_args, rc=None):
		rc = c.rowcount if rc is None else c.rowcount == rc
		if self.debug and not rc: raise LookupError(*lookup_args)

	@cl.contextmanager
	def tx(self):
		'External transaction context to group multiple ORM calls together'
		if not self._tx: tx = self._tx = self._db.__enter__()
		else: tx = None
		try: yield tx
		finally:
			if tx: self._db.__exit__(*sys.exc_info())

	def host_map_get(self):
		with self() as c:
			c.execute( 'select path, mtime, host, chk, policy'
				' from host_files left join hosts on path = host_file order by path' )
			return dict(
				(p, host_file( p, rows[0][1],
					dict((h, host_info(h, chk, policy)) for _, _, h, chk, policy in rows if h) ))
				for p, rows in ( (pl.Path(p), list(rows))
					for p, rows in it.groupby(c.fetchall(), key=op.itemgetter(0)) ) )

	def host_file_update(self, p, mtime, hosts0, hosts1):
		p = str(p)
		with self() as c:
			c.execute('savepoint ins')
			try: c.execute('insert into host_files (path, mtime) values (?, ?)', (p, mtime))
			except self._sqlite.IntegrityError:
				c.execute('rollback to ins')
				c.execute('update host_files set mtime = ? where path = ?', (mtime, p))
				if not c.rowcount: raise LookupError(p)
			c.execute('release ins')
			for hi in hosts1.values():
				if hosts0.get(hi.host, ...) == hi: continue
				c.execute(
					'insert or replace into hosts (host_file, host, chk, policy)'
					' values (?, ?, ?, ?)', (p, hi.host, hi.chk or 'https', hi.policy) )
			if h_set_del := set(hosts0).difference(hosts1):
				h_set_tpl = ', '.join('?'*len(h_set_del))
				c.execute(f'delete from hosts where host in ({h_set_tpl})', tuple(h_set_del))

	def host_file_cleanup(self, p_iter):
		if not (p_set := set(map(str, p_iter))): return
		with self() as c:
			p_set_tpl = ', '.join('?'*len(p_set))
			c.execute(f'delete from host_files where path in ({p_set_tpl})', tuple(p_set))

	def _st_val(self, s):
		'State str to bool/none, used for both host and addr states.'
		# "skipped" is addr state for when curl can't be run
		# "failing" is a host state, same as "ok" except for alt-route checks
		if not s or s == 'skipped': return None
		elif s in ['ok', 'failing', 'unstable']: return True
		elif not isinstance(s, str): raise ValueError(s)
		else: return False

	def _st_str(self, v):
		'State bool/none/str to str for db field.'
		return {True: 'ok', False: 'na', None: 'skipped'}.get(v, v)

	_host_check = cs.namedtuple('HostCheck', 't p host state')
	def host_checks(self, ts_max, n, force_host=None):
		with self() as c:
			chk, val = ( ('ts_check <= ?', ts_max)
				if not force_host else ('host = ?', force_host) )
			c.execute( 'select host, state, chk, policy from hosts'
				f' where {chk} order by ts_check limit ?', (val, n) )
			return list(
				self._host_check( chk_tuple(chk),
					self._chk_policy(policy), host, self._st_val(s) )
				for host, s, chk, policy in c.fetchall() )

	def host_update(self, ts, host, addrs=list(), addr_timeout=None, addr_limit=None):
		with self() as c:
			c.execute('update hosts set ts_check = ? where host = ?', (ts, host))
			self._upd_check(c, host)

			for addr in set(ip.ip_address(addr) for addr in addrs):
				addr = addr.compressed
				c.execute('savepoint ins')
				try:
					c.execute( 'insert into addrs'
						' (host, addr, ts_seen) values (?, ?, ?)', (host, addr, ts) )
				except self._sqlite.IntegrityError:
					c.execute('rollback to ins')
					c.execute( 'update addrs set ts_seen = ?'
						' where host = ? and addr = ?', (ts, host, addr) )
					self._upd_check(c, host, addr)

			ts_cutoff = addr_timeout and (ts - addr_timeout)
			if addr_limit:
				c.execute( 'select ts_seen from addrs where host = ?'
					' order by ts_seen desc limit 1 offset ?', (host, addr_limit) )
				ts_cutoff = max(ts_cutoff or 0, (c.fetchall() or [[0]])[0][0])
			if ts_cutoff:
				c.execute( 'delete from addrs where'
					' host = ? and ts_seen < ?', (host, ts_cutoff) )

	_addr_check = cs.namedtuple('AddrCheck', 't p host host_st addr addr_last state')
	def addr_checks(self, ts_max, n, failing=False, force_host=None):
		with self() as c:
			if force_host: chk, chk_vals = 'host = ?', [force_host]
			elif failing:
				chk, chk_vals = ( 'addrs.state != ?'
					' and ts_check_failing <= ?', ['ok', ts_max] )
			else: chk, chk_vals = 'addrs.ts_check <= ?', [ts_max]
			if failing:
				chk += ' and hosts.state in (?, ?)'
				chk_vals.extend(['failing', 'unstable'])
			c.execute(
				'with tsl as (select host, max(ts_seen) as tsl from addrs group by host)'
				'select chk, policy, host, hosts.state, addr, ts_seen = tsl, addrs.state'
				f' from addrs join hosts using (host) join tsl using (host) where {chk}'
				' order by addrs.ts_check limit ?', (*chk_vals, n) )
			return list(
				self._addr_check( chk_tuple(chk), self._chk_policy(policy),
					host, self._st_val(sh), ip.ip_address(addr), tsl, self._st_val(sa) )
				for chk, policy, host, sh, addr, tsl, sa in c.fetchall() )

	def addr_update(self, ts, host, addr, state0, state1):
		with self() as c:
			if state0 == state1: upd, upd_args = '', list()
			else:
				upd = ', state = ?, ts_update = ?'
				upd_args = self._st_str(state1), ts
			addr = ip.ip_address(addr).compressed
			c.execute( 'update addrs set'
				' ts_down = case when ts_down >= ts_check then ts_update else 0 end,'
				f' ts_check = ?{upd}  where host = ? and addr = ?', (ts, *upd_args, host, addr) )
			self._upd_check(c, host, addr)
			return state1 and state1 is True

	def addr_update_failing(self, ts, ac, ad):
		with self() as c:
			for is_down, ast in enumerate([ac.difference(ad), ad]):
				if not (ast := list(ip.ip_address(addr).compressed for addr in ast)): continue
				down, vals = (', ts_down = ?', [ts]) if is_down else ('', [])
				c.execute( f'update addrs set ts_check_failing = ?{down} where'
					f' addr in ({", ".join("?"*len(ast))}) and state != ?', (ts, *vals, *ast, 'ok') )
				self._upd_check(c, ast, rc=len(ast))

	_policy_host_upd = cs.namedtuple('PolicyHostUpdate', 't p host state0 state')
	def host_state_sync(self, ts, td_ok, td_na, hosts):
		# Host state changes always bump ts_update, and go like this:
		#  ??? -> [ok, na] ::
		#  ok -[chk-fail]-> failing :: na (ts<now-td_ok) -[chk-ok]-> ok ::
		#  failing -[chk-ok]-> ok :: failing -[chk-fail + td_na]-> na
		# "ok" with some addrs having ts_down set = "unstable".
		# Outside of db, "failing" and "unstable" translate to True, same as "ok".
		# Returns ok/blocked changes, without ok -> failing and such.
		changes, st_updates = list(), cs.defaultdict(set)
		with self() as c:
			c.execute(
				'with tsl as (select host, max(ts_seen) as tsl from addrs group by host)'
				'select  host, chk, policy, addr, hosts.ts_update, hosts.state,'
					' addrs.state, addrs.ts_update, addrs.ts_down, addrs.ts_seen = tsl'
				' from addrs join hosts using (host) left join tsl using (host)'
				f' where host in ({",".join("?"*len(hosts))}) order by host', tuple(hosts) )
			for host, host_tuples in it.groupby(c.fetchall(), key=op.itemgetter(0)):
				sas, policy = (set(), set(), set(), set()), None
				for host, chk, policy, addr, ts_upd, shs, sa, ts_au, ts_ad, ts_last in host_tuples:
					if ts_ad >= ts_au: sa = None; st_updates['unstable'].add(host)
					else: sa = self._st_val(sa)
					sas[ts_last*2 + (':' in addr)].add(sa)
				sh, td_upd = self._st_val(shs), ts - ts_upd
				sa = policy_host_state(policy := self._chk_policy(policy), *sas)

				if sa != sh:
					# log.debug(
					# 	'host-upd: {} sa={} sh={}[{}] time[ since-upd={} to-ok={} to-na={} ]',
					# 	host, sa, sh, shs, *map(td_fmt, [td_upd, td_ok, td_na]) )
					if sa and td_upd < td_ok: continue # "na" host-state, all-ok on addrs, but too soon
					if not sa:
						if shs == 'ok': st_updates['failing'].add(host); continue
						elif td_upd < td_na: continue # delays failing/unstable -> na transition
					changes.append(self._policy_host_upd(chk_tuple(chk), policy, host, sh, sa))
					st_updates[self._st_str(sa)].add(host)
				elif sa and shs not in ['ok', 'na']: st_updates['ok'].add(host) # failing/unstable -> ok

			hss = set()
			st_updates['ok'].update(st_updates.pop('skipped', set())) # no addrs = ok
			for st in 'na', 'failing', 'unstable', 'ok':
				if not (hs := st_updates.pop(st, set())): continue
				hs.difference_update(hss); hss.update(hs)
				hs_tpl = ', '.join('?'*len(hs))
				c.execute( 'update hosts set state = ?,'
					f' ts_update = ? where host in ({hs_tpl})', (st, ts, *hs) )
				self._upd_check(c, st, hs, rc=len(hs))
			if st_updates: raise ValueError(st_updates)
		return changes

	_policy_line = cs.namedtuple( 'PolicyLine',
		't p host state state_ts addr addr_st addr_st_ts addr_last' )
	def host_state_policy(self, hosts=None, addrs=None, st_raw=False):
		with self() as c:
			chk, chk_vals = '', list()
			if hosts:
				chk += 'and host in (' + ','.join('?'*len(hosts)) + ')'
				chk_vals.extend(hosts)
			if addrs:
				chk += 'and addr in (' + ','.join('?'*len(addrs)) + ')'
				chk_vals.extend(a.compressed for a in addrs)
			c.execute(
				'with tsl as (select host, max(ts_seen) as tsl from addrs group by host)'
				' select host, chk, policy, hosts.state, hosts.ts_update,'
					' addr, addrs.state, addrs.ts_update, addrs.ts_seen = tsl'
				' from hosts left join addrs using (host) join tsl using (host)'
				f' where addr not null {chk}'
				' order by host, ts_seen != tsl, addr like ?, addr', (*chk_vals, '%:%') )
			st = self._st_val if not st_raw else lambda v: v
			return list(
				self._policy_line( chk_tuple(chk), self._chk_policy(p),
					host, st(s), s_ts, ip.ip_address(addr), st(sa), sa_ts, sa_tsl )
				for host, chk, p, s, s_ts, addr, sa, sa_ts, sa_tsl in c.fetchall() )


### Main check-runner daemon

class NBRPC:

	def __init__(self, conf):
		self.conf, self.log = conf, get_logger()
		self.timers = dict()

	def close(self):
		if self.db: self.db = self.db.close()
	def __enter__(self):
		self.db = NBRPDB( self.conf.db_file, self.conf.host_policy_default,
			lock_timeout=self.conf.db_lock_timeout, debug=self.conf.db_debug )
		self.host_map = None
		return self
	def __exit__(self, *err): self.close()

	def log_td(self, tid, log_fmt=None, *log_args, warn=False, err=False):
		if not log_fmt:
			self.timers[tid] = time.monotonic()
			return
		td_str = td_fmt(td := time.monotonic() - self.timers[tid])
		if log_fmt is ...: return td_str
		if err: self.log.error(log_fmt, *log_args, td=td_str)
		elif warn: self.log.warning(log_fmt, *log_args, td=td_str)
		elif td < self.conf.timeout_log_td_info:
			self.log.debug(log_fmt, *log_args, td=td_str)
		else: self.log.info(f'[SLOW] {log_fmt}', *log_args, td=td_str)

	def sleep( self, seconds,
			sigset={signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT} ):
		if sig_info := signal.sigtimedwait(sigset, seconds):
			sig_handler = signal.getsignal(sig_info.si_signo)
			if callable(sig_handler): sig_handler(sig_info.si_signo, None) # INT/TERM
			self.log.debug( 'Interrupted sleep-delay'
				' on signal: {}', signal.Signals(sig_info.si_signo).name )

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
			if abs( (hf := self.host_map.get(
				p, host_file(p, 0, dict()) )).mtime - mtime ) < 0.01: continue
			hosts = dict((hi.host, hi) for hi in map(
				chk_parse, (list() if not mtime else it.chain.from_iterable(
					_re_rem.sub('', line).split() for line in p.read_text().splitlines() )) ))
			for hi in hosts.values(): chk_tuple(hi.chk); chk_policy(hi.policy) # validate
			self.db.host_file_update(p, mtime, hf.hosts, hosts)
			self.host_map[p] = host_file(p, mtime, hosts)
			if hf.hosts != hosts:
				self.log.info('Hosts-file update: {} ({:,d} host[s])', host_fns[p], len(hosts))
		host_files_del = set(self.host_map).difference(host_files)
		for p in host_files_del:
			self.log.info('Hosts-file removed: {}', host_fns[p])
			del self.host_map[p]
		self.db.host_file_cleanup(host_files_del)

	def print_checks(self, line_len=110, line_len_diff=-16):
		with cl.suppress(OSError): line_len = os.get_terminal_size().columns + line_len_diff
		st_map = { None: '???', 'ok': 'OK',
			'na': 'blocked', 'failing': '-failing-', 'unstable': '/unstable/' }
		for host, pls in sorted( ( (host, list(pls)) for host, pls in
					it.groupby(self.db.host_state_policy(st_raw=True), key=op.attrgetter('host')) ),
				key=lambda host_pls: host_pls[0][::-1] ):
			for n, pl in enumerate(pls):
				if not n:
					print( f'\n{pl.host} [{pl.t.s}'
						f' {st_map[pl.state]} @ {ts_fmt(pl.state_ts)}]:' )
				line = ( ' ' + ' *'[pl.addr_last] + pl.addr.compressed
					+ f' :: [{ts_fmt(pl.addr_st_ts)}] {pl.addr_st or "???"}' )
				if len(line) > line_len: line = line[:line_len-3] + '...'
				print(line)
		print()

	def print_unbound_zone(self, spec):
		policy = re.search('^([+*>@%]*)', spec)
		policy, spec = policy.group(), spec[policy.end():]
		if policy: policy = chk_policy(policy.translate(str.maketrans('+*>@%', '46DLR')))
		re_host = re.compile(spec)
		for host, addrs in it.groupby(
				self.db.host_state_policy(), key=op.attrgetter('host') ):
			if not re_host.search(host): continue
			records, ap = list(), None
			for st in addrs:
				rt, ap = ['A', 'AAAA'][st.addr.version == 6], policy or st.p
				if ap.dns_st is not None:
					if ap.dns_st is not st.addr_st: continue
				if ap.dns_af:
					if (rt == 'A') is not ('6' not in ap.dns_af.name): continue
				if ap.dns_last and not st.addr_last: continue
				records.append(f"local-data: '{st.host} {rt} {st.addr.compressed}'")
			if ap:
				if ap.dns_shuf: random.shuffle(records)
				for line in [f'\nlocal-zone: {st.host}. static'] + sorted(records): print(line)


	def run(self):
		c, tsm_checks = self.conf, time.monotonic()
		while True:
			self.host_map_sync()

			if not (force_n := c.update_n):
				force_n, c.update_all = c.update_all and 2**32, False
			changes = self.run_checks( ts_now(),
				force_n=force_n, force_host=c.update_host )
			force_sync, c.update_sync = c.update_sync, False
			if changes or force_sync: self.policy_replace()
			if c.update_host or c.update_n: break

			tsm = time.monotonic()
			while tsm_checks <= tsm: tsm_checks += c.td_checks
			delay = tsm_checks - tsm
			self.log.debug('Delay until next checks: {:,.1f}', delay)
			self.sleep(delay)

	def run_checks(self, ts, force_n=None, force_host=None):
		if force_host: force_n = 2**32

		## Resolve/update host addrs
		host_checks = self.db.host_checks(
			(ts - self.conf.td_host_addrs) if not force_n else ts,
			force_n or self.conf.limit_iter_hosts, force_host )
		self.log_td('hosts')
		for chk in host_checks:
			if self.conf.fake_results:
				addrs = list(r.addr for r in self.conf.fake_results.get(chk.host, list()))
			else:
				self.log_td('gai')
				try:
					addrs = set(filter( op.attrgetter('is_global'),
						(ip.ip_address(ai[4][0]) for ai in socket.getaddrinfo(
							chk.host, port=chk.t.svc, family=chk.p.dns_af,
							type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP )) ))
					if not addrs: raise OSError('No valid address results')
				except OSError as err:
					addrs = list()
					self.log_td( 'gai', 'Host getaddrinfo: {} {}'
						' [{td}] - {}', chk.host, chk.t.svc, err_fmt(err) )
				else:
					self.log_td( 'gai', 'Host getaddrinfo: {} {}'
						' [addrs={} {td}]', chk.host, chk.t.svc, len(addrs) )
			self.db.host_update( ts, chk.host, addrs,
				addr_timeout=self.conf.timeout_host_addr, addr_limit=self.conf.limit_addrs_per_host )
		if host_checks: # these can change host-states over time, not only with addr states
			self.log_td( 'hosts', 'Finished host-addrs'
				' update [{td}]: {}', ' '.join(chk.host for chk in host_checks) )

		## Check address availability
		addr_checks = set(self.db.addr_checks(
			(ts - self.conf.td_addr_state) if not force_n else ts,
			force_n or self.conf.limit_iter_addrs, force_host=force_host ))
		if addr_checks:
			self.log_td('addrs')
			checks_str = ' '.join(chk.addr.compressed for chk in addr_checks)
			if len(checks_str) > 80: checks_str = f'[{len(addr_checks):,d}] {checks_str[:70]}...'
			self.log.debug('Running address checks: {}', checks_str)
			res = self.run_addr_checks(addr_checks)
			n_fail = len(res) - (n_ok := sum((r is True) for r in res.values()))
			self.log_td( 'addrs', 'Finished host-addrs check [ok={} fail={}'
				' skip={} {td}]: {}', n_ok, n_fail, len(addr_checks) - len(res), checks_str )
			for chk in sorted(addr_checks, key=lambda chk: (chk.host, chk.addr.compressed)):
				res_str = {True: 'ok', False: 'na', None: '???'}.get(s := res.get(chk.addr), s)
				self.log.debug( 'Host-addr check: {} [{} {}] - {}',
					chk.addr.compressed, chk.t.s, chk.host, res_str )
				st = self.db.addr_update( ts, chk.host,
					chk.addr, chk.state, res.get(chk.addr) )
				if st == chk.state: addr_checks.remove(chk)

		## Check if any host states should be flipped
		if force_host: td_ok = td_na = 0
		else: td_ok, td_na = self.conf.td_host_ok_state, self.conf.td_host_na_state
		host_state_changes = self.db.host_state_sync(
			ts, td_ok, td_na, set(chk.host for chk in host_checks) )
		if host_state_changes:
			st_map = {None: '???', True: 'OK', False: 'blocked'}
			for phu in host_state_changes:
				self.log.info( 'Host state updated ({}): {} = {} -> {}',
					phu.t.s, phu.host, st_map[phu.state0], st_map[phu.state] )
		if host_policy_updates := policy_host_updates(
				set(phu.host for phu in host_state_changes), addr_checks ):
			self.policy_update(host_policy_updates)
		return bool(host_policy_updates)


	def run_failing(self):
		c, tsm_checks = self.conf, time.monotonic()
		while True:
			if not (force_n := c.update_n):
				force_n, c.update_all = c.update_all and 2**32, False
			self.run_failing_checks( ts_now(),
				force_n=force_n, force_host=c.update_host )
			if c.update_host or c.update_n: break
			tsm = time.monotonic()
			while tsm_checks <= tsm: tsm_checks += c.td_checks
			delay = tsm_checks - tsm
			self.log.debug('Delay until next failing-rechecks: {:,.1f}', delay)
			self.sleep(delay)

	def run_failing_checks(self, ts, force_n=None, force_host=None):
		if force_host: force_n = 2**32
		addr_checks = self.db.addr_checks(
			(ts - self.conf.td_addr_state) if not force_n else ts,
			force_n or self.conf.limit_iter_addrs, failing=True, force_host=force_host )
		if not addr_checks: return

		self.log_td('addrs')
		checks_str = ' '.join(chk.addr.compressed for chk in addr_checks)
		if len(checks_str) > 80: checks_str = f'[{len(addr_checks):,d}] {checks_str[:70]}...'
		self.log.debug('Running failing addr-checks: {}', checks_str)

		res = self.run_addr_checks(addr_checks)
		n_fail = len(res) - (n_ok := sum((r is True) for r in res.values()))
		self.log_td( 'addrs', 'Finished failing host-addrs check [ok-here={}'
			' down-too={} skip={} {td}]: {}', n_ok, n_fail, len(addr_checks) - len(res), checks_str )
		addrs_down = set(addr for addr, r in res.items() if r is False)
		addrs_chk = set(chk.addr for chk in addr_checks)

		if addrs_down:
			checks_str = ' '.join(addr.compressed for addr in addrs_down)
			if len(checks_str) > 80: checks_str = f'[{len(addrs_down):,d}] {checks_str[:70]}...'
			self.log.debug('Confirmed-down host-addrs: {}', checks_str)
		self.db.addr_update_failing(ts, addrs_chk, addrs_down)


	def run_addr_checks(self, addr_checks):
		addr_checks_curl, addr_checks_res = dict(), dict()
		for chk in addr_checks:
			if chk.t.s == 'dns': addr_checks_res[chk.addr] = True
			elif chk.t.s in ['http', 'https']: addr_checks_curl[chk.addr] = chk
			else: self.log.warning('Skipping not-implemented check type: {}', chk.t.s)
		if not addr_checks_curl: return addr_checks_res

		curl_res_default = '200/301/302'
		if self.conf.fake_results:
			for chk in addr_checks_curl.values():
				if not (r := self.conf.fake_results.get(chk.addr)): continue
				addr_checks_res[r.addr] = any(
					(not r.chk or (int(n.strip() or -1) == int(r.chk)))
					for n in (chk.t.res or curl_res_default).split('/') )
			return addr_checks_res

		curl_ports = dict(http=80, https=443)
		curl_to, curl_fmt = self.conf.timeout_addr_check, (
			'%{urlnum} %{response_code} %{time_total}'
			' :: %{exitcode} %{ssl_verify_result} :: %{errormsg}\n' )
		curl_cmd = [ self.conf.curl_cmd, '--disable', '--config', '-',
			'--parallel', '--parallel-immediate', '--max-time', str(curl_to) ]
		if not addr_checks_curl: curl = None
		elif self.conf.curl_cmd_debug:
			p_err(f'--- curl cmd (stdin-config follows on stdout):\n  {" ".join(curl_cmd)}')
			curl = sp.Popen(['cat'], stdin=sp.PIPE)
		else: curl = sp.Popen(curl_cmd, stdin=sp.PIPE, stdout=sp.PIPE)

		def curl_term(sig=None, frm=None):
			nonlocal curl
			if not curl: return
			if sig:
				self.log_td( 'addrs', 'Terminating curl pid'
					' after timeout [limit={:,.1f}s {td}]', curl_to, warn=True )
			try:
				curl.terminate()
				try: curl.wait(self.conf.timeout_kill)
				except sp.TimeoutExpired: curl.kill()
			except ProcessLookupError: pass
			finally: curl, proc = None, curl
			proc.wait()

		signal.signal(signal.SIGALRM, curl_term)
		signal.alarm(round(curl_to * 1.5))
		try:
			# Can also check tls via --cacert and --pinnedpubkey <hashes>
			res_map = dict()
			for n, chk in enumerate(addr_checks_curl.values()):
				host, addr, port = chk.host, chk.addr.compressed, curl_ports[chk.t.svc]
				try:
					res_map[chk.t.res] = set( int(n.strip() or -1)
						for n in (chk.t.res or curl_res_default).split('/') )
				except Exception as err:
					self.log.warning( 'Skipping check with invalid result-spec'
						' [type={} host={}]: {!r} - {}', chk.t.s, chk.host, chk.t.res, err_fmt(err) )
					continue
				if ':' in addr: addr = f'[{addr}]'
				if n: curl.stdin.write(b'next\n')
				curl.stdin.write('\n'.join([ '',
					f'url = "{chk.t.s}://{host}:{port}{chk.t.ext or "/"}"',
					f'resolve = {host}:{port}:{addr}', # --connect-to can also be used
					f'user-agent = "{self.conf.curl_ua}"',
					f'connect-timeout = {curl_to}', f'max-time = {curl_to}',
					*'silent disable globoff fail no-keepalive no-sessionid tcp-fastopen'.split(),
					f'write-out = "{curl_fmt}"', 'output = /dev/null', '' ]).encode())
			curl.stdin.flush(); curl.stdin.close()
			if self.conf.curl_cmd_debug: exit(curl.wait())

			addr_idx = list(addr_checks_curl)
			for line_raw in curl.stdout:
				try:
					line = line_raw.decode().strip().split('::', 2)
					n, code, td = line[0].split()
					(chk_res, tls_err), curl_msg = line[1].split(), line[2]
					try: td = td_fmt(float(td))
					except: pass
					chk_res, chk = int(chk_res), addr_checks_curl[addr_idx[int(n)]]
					code_chk, code = res_map[chk.t.res], 0 if not code.isdigit() else int(code)
					if not code:
						chk_res = ( f'curl conn-fail'
							f' [err={chk_res} tls={tls_err} {td}]: {curl_msg.strip()}' )
					elif code not in code_chk:
						chk_res = '/'.join(map(str, code_chk))
						chk_res = f'curl http-fail [http={code}:{chk_res} {td}]'
					else: chk_res = True
					addr_checks_res[chk.addr] = chk_res
				except Exception as err:
					self.log.exception('Failed to process curl status line: {}', line)

		finally:
			signal.alarm(0)
			curl_term()
		return addr_checks_res

	def run_policy_cmd(self, hook, policy_func):
		if not (p := getattr(self.conf, f'policy_{hook}_cmd')): return
		policy = policy_func()
		self.log_td('pu')
		if not self.conf.policy_socket:
			if p == ['-']: return print(policy.decode().rstrip())
			try:
				sp.run( p, check=True,
					timeout=self.conf.timeout_policy_cmd, input=policy )
			except sp.TimeoutExpired:
				self.log_td( 'pu', 'Policy-{} command timeout'
					' [limit={:,.1f} {td}]', hook, self.conf.timeout_policy_cmd, err=True )
			except sp.CalledProcessError as err:
				self.log_td('pu', 'Policy-{} command error [{td}]: {}', hook, err_fmt(err), err=True)
			else: self.log_td('pu', 'Policy-{} command success [{td}]', hook)
		else:
			p, = p
			try:
				with socket.socket(socket.AF_UNIX) as s:
					s.settimeout(self.conf.timeout_policy_cmd)
					s.connect(p)
					s.sendall(policy.strip() + b'\n\n')
					if (ack := s.recv(3)) != b'OK\n':
						raise BrokenPipeError(f'Invalid ACK reply [ {ack} ]')
			except OSError as err:
				self.log_td( 'pu', 'Policy-{} socket error [timeout={:,.1f} {td}]:'
					' {}', hook, self.conf.timeout_policy_cmd, err_fmt(err), err=True )
			else: self.log_td('pu', 'Policy-{} socket-send success [{td}]', hook)

	def policy_fetch(self, hosts=None, addrs=None):
		pis = list()
		for host, pls in it.groupby(
				self.db.host_state_policy(hosts, addrs), key=op.attrgetter('host') ):
			addr_sts = dict()
			for pl in pls: addr_sts[pl.addr] = pl.addr_st
			pis.append(policy_info(host, pl.state, pl.p, pl.t.s, addr_sts))
		return pis

	def policy_update(self, host_updates):
		self.run_policy_cmd( 'update',
			lambda: policy_dump(self.policy_fetch(
				set(h for h,addrs in host_updates.items() if not addrs),
				set(it.chain.from_iterable(host_updates.values())) )) )

	def policy_replace(self):
		self.run_policy_cmd('replace', lambda: policy_dump(self.policy_fetch()))


### CLI

def conf_opt_info(conf):
	intervals, timeouts, limits, p = list(), list(), list(), pl.Path(__file__)
	prefixes = ('td_', intervals), ('timeout_', timeouts), ('limit_', limits)
	try:
		if p.name.endswith('.pyc'): raise ValueError
		lines = p.read_bytes()
		if not lines.startswith(b'#!/usr/bin/env'): raise ValueError
		p, lines = None, list(str.strip(line) for line in p.read_text().splitlines())
	except: p = lines = None
	if not lines: # pyinstaller and such
		for pre, dst in prefixes:
			dst.extend(textwrap.fill(
				' '.join(
					f'{k[len(pre):].replace("_","-")}={getattr(conf, k)}'
					for k in dir(conf) if k.startswith(pre) ),
				width=60, break_long_words=False, break_on_hyphens=False ).splitlines())
	else: # much nicer opts with comments
		for line in lines:
			if line == 'class NBRPConfig:': p = True
			elif p and line.startswith('class '): break
			elif not p: continue
			for pre, dst in prefixes:
				if not line.startswith(pre): continue
				k, v = map(str.strip, line.split('=', 1))
				dst.append(f'- {k.removeprefix(pre).replace("_","-")} = {v}')
	return intervals, timeouts, limits

def main(args=None, conf=None):
	if not conf: conf = NBRPConfig()
	info_intervals, info_timeouts, info_limits = conf_opt_info(conf)

	import argparse
	dd = lambda text: re.sub( r' \t+', ' ',
		textwrap.dedent(text).strip('\n') + '\n' ).replace('\t', '  ')
	parser = argparse.ArgumentParser(
		usage='%(prog)s [options] -f hosts.txt ...',
		formatter_class=argparse.RawTextHelpFormatter, description=dd('''
			Run host resolver, availability checker and routing policy controller.
			Use --debug option to get more info on what script is doing.
			SIGHUP and SIGQUIT signals (Ctrl-\\ in a typical terminal) can be used
				to skip delays, and SIGHUP also runs -x/--policy-replace-cmd, if enabled.'''))

	parser.add_argument('-f', '--check-list-file',
		action='append', metavar='path', default=list(), help=dd('''
			File with a list of services/endpoints to monitor
				for availability and add alternative routes to, when necessary.
			Format for each spec is: hostname[>policy][:check-type][=expected-result]
				See README file for expanded meaning and examples of components there.
			Specs can be separated by spaces or newlines.
			Anything from # characters to newline is considered a comment and ignored.
			Can be missing and/or created/updated on-the-fly,
				with changes picked-up after occasional file mtime checks.
			Has to be specified in a normal operation mode, not needed for
				-P/--print-state, -F/--failing-checks and other modes that don't run normal checks.'''))
	parser.add_argument('-d', '--db', metavar='path', default=conf.db_file.name,
		help='Path to sqlite database used to track host states. Default: %(default)s')
	parser.add_argument('-p', '--check-list-default-policy',
		metavar='spec', default='af-all', help=dd('''
			Default value for per-host "policy", if not specified in -f/check-list-file for the host.
			Same meaning for these as in ">policy" component for specs in that file.
			See README file for info on all possible values for it. Default: %(default)s.'''))
	parser.add_argument('-U', '--update-all', action='store_true',
		help='Force-update all host addresses and availability statuses on start.')
	parser.add_argument('-S', '--sync-on-start',
		action='store_true', help='Issue full policy replace on script startup.')

	group = parser.add_argument_group('Different/oneshot operation modes')
	group.add_argument('-P', '--print-state', action='store_true',
		help='Print current state of all host and address checks from db and exit.')
	group.add_argument('-u', '--update-host', metavar='host', help=dd('''
		Force check/update specified host status and exit.
		This runs hostname check, all of relevant address
			checks and force-updates availability status from those,
			regardless of any grace period(s) and timeouts for this host.
		Can be combined with -S/--sync-on-start to force-replace policy before exit.'''))
	group.add_argument('-F', '--failing-checks', action='store_true', help=dd('''
		Special mode that only bumps grace period for ok -> failing -> n/a
			state transition for endpoints if check for that endpoint fails in this instance too.
		Script in this mode is intended to be run through separate network connection,
			preventing endpoint from transitioning into "n/a" state if it appears to be down
			through that additional network perspective as well, e.g. due to some service outage.
		Only re-checks endpoints for hosts that are in a "failing" state,
			so requires main script instance to create/mark such in the database.
		Limit/interval/timeout opts that apply to main loop and checks are used here as well,
			e.g. "checks" interval between db checks, "addr-state" between per-addr checks, etc.
		Does not need/use -f/--check-list-file option.'''))
	group.add_argument('-Z', '--unbound-zone-for', metavar='regexp', help=dd('''
		Generate local YAML zone-file for regexp-specified hosts to stdout and exit.
		It's intended to be included in Unbound DNS resolver config via "include:" directive.
		Static local-zone and local-data directives there are to lock specified
			host(s) to only use IPs from database that's been checked by this script,
			to avoid application errors due to them resolving same name(s) to some diff ones.
		Specified regexp (python re format) should match host(s)
			in the database, empty output will be produced on no match.
		Returned addresses can be also filtered by using following prefix(-es) before regexp:
			@ - limit to only addrs seen in last in getaddrinfo() result for hostname;
			%% - return records in shuffled order; > - only directly-accessible addrs;
			+ - A (IPv4) only; * - AAAA (IPv6) only.
		Using these flags disregards any per-host DNS filtering policies, if specified.
		Make sure this script doesn't use such restricted resolver itself.'''))
	group.add_argument('-n', '--force-n-checks', type=int, metavar='n',
		help='Run n forced checks for hosts and their addrs and exit, to test stuff.')

	group = parser.add_argument_group('Check/update scheduling options')
	group.add_argument('-i', '--interval',
		action='append', metavar='interval-name=seconds', default=list(), help=dd('''
			Change specific interval value, in interval-name=seconds format.
			Can be used multiple times to change different intervals.
			Supported intervals with their default values:''')
		+ ''.join(f' {line}\n' for line in info_intervals))
	group.add_argument('-t', '--timeout',
		action='append', metavar='timeout-name=seconds', default=list(),
		help='Same as -i/--interval above, but for timeout values.'
			' Supported timeouts:\n' + ''.join(f' {line}\n' for line in info_timeouts))
	group.add_argument('-l', '--limit',
		action='append', metavar='limit-name=seconds', default=list(),
		help='Same as -i/--interval above, but for limit values.'
			' Supported limits:\n' + ''.join(f' {line}\n' for line in info_limits))

	group = parser.add_argument_group('External hook scripts')
	group.add_argument('-X', '--policy-update-cmd', metavar='command', help=dd('''
		Command to add/remove routing policy rules for specific IP address(-es).
		Will be piped lines for specific policy changes to stdin, for example:
			ok google.com 142.250.74.142 https
			ok google.com 2a00:1450:4010:c0a::65 https
			na example.com 1.2.3.4 http
		There "ok" means that host's address(-es) are now available for direct connections.
			"na" is for unavailable services that should be routed through the tunnel or whatever.
		If command includes spaces, then it will be split into binary/arguments on those.
		Script is expected to exit with 0 code, otherwise error will be logged.
		Command can be "-" to simply print policy lines to stdout, for testing.
		These lines indicate latest policy updates, not the full state of it,
			for which there's -x/--policy-replace-cmd option, that should be more reliable.'''))
	group.add_argument('-x', '--policy-replace-cmd', metavar='command', help=dd('''
		Same as --policy-update-cmd option above, but always get piped a full state instead.
		Should be more reliable for atomic ruleset updates and stuff like that.'''))
	group.add_argument('-s', '--policy-socket', action='store_true', help=dd('''
		Modifies --policy-*-cmd options to write same rules
			to a unix socket at that path, instead of binary's stdin.
		New connection is made each time, output ends with an empty line,
			and single "OK" response-line from the other end, otherwise error is logged.
		Can be used to separate/sandbox unprivileged "tester" part of the script easily.'''))

	group = parser.add_argument_group('Logging and debug options')
	group.add_argument('-q', '--quiet', action='store_true',
		help='Do not log info about updates that normally happen, only bugs and anomalies.')
	group.add_argument('--debug', action='store_true', help=dd('''
		Enables verbose logging and some extra db sanity-checks,
			which can normally fail on race conditions with concurrent db access.'''))
	group.add_argument('--debug-curl-cmd', action='store_true',
		help='Print command and configuration of first curl that script runs and exit.')

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	if opts.debug and not opts.print_state: log = logging.DEBUG
	elif opts.quiet: log = logging.WARNING
	else: log = logging.INFO
	logging.basicConfig(format='%(levelname)s :: %(message)s', level=log)
	log = get_logger()

	conf.host_files = list(pl.Path(p) for p in opts.check_list_file)
	if not ( conf.host_files or opts.print_state
			or opts.failing_checks or opts.unbound_zone_for ):
		parser.error('No check-list files specified')
	conf.curl_cmd_debug = opts.debug_curl_cmd

	conf.db_file, conf.policy_socket = pl.Path(opts.db), opts.policy_socket
	conf.update_all, conf.update_sync = opts.update_all, opts.sync_on_start
	conf.update_host, conf.update_n = opts.update_host, opts.force_n_checks
	conf.host_policy_default = chk_policy(opts.check_list_default_policy)
	for pre, kvs, opt in ( ('td_', opts.interval, '-i/--interval'),
			('timeout_', opts.timeout, '-t/--timeout'), ('limit_', opts.limit, '-l/--limit') ):
		for kv in kvs:
			try:
				k, v = kv.split('=', 1)
				conv = type(getattr(conf, k := pre + k.replace('-', '_')))
				setattr(conf, k, conv(v))
			except: parser.error(f'Failed to parse {opt} value: {kv!r}')
	for k in 'update', 'replace':
		if v := (getattr(opts, ck := f'policy_{k}_cmd') or '').strip(): setattr(conf, ck, v.split())
	if opts.debug: conf.db_debug = True

	if results_file := os.environ.get('NBRPC_TEST_RUN'):
		_res_line = cs.namedtuple('Result', 'host addr chk')
		results = conf.fake_results = cs.defaultdict(list)
		for res in pl.Path(results_file).read_text().split():
			if '=' not in res: host, res = res, None
			else: host, res = res.split('=', 1)
			if '@' in host: host, addr = host.split('@', 1)
			else: host, addr = '', host
			res = results[res.addr] = _res_line(host, ip.ip_address(addr), res)
			results[res.host].append(res)

	for sig in signal.SIGINT, signal.SIGTERM:
		signal.signal( sig, lambda sig,frm:
			log.debug('Exiting on {} signal', signal.Signals(sig).name) or sys.exit(os.EX_OK) )
	with NBRPC(conf) as nbrpc:
		if opts.print_state: return nbrpc.print_checks()
		if opts.unbound_zone_for: return nbrpc.print_unbound_zone(opts.unbound_zone_for)
		signal.signal(signal.SIGQUIT, lambda sig,frm: None)
		signal.signal(signal.SIGHUP, lambda sig,frm: setattr(conf, 'update_sync', True))
		if not opts.failing_checks:
			log.debug('Starting nbrpc main loop...')
			nbrpc.run()
		else:
			log.debug('Starting nbrpc main loop (failing-checks-confirm mode)...')
			nbrpc.run_failing()
		log.debug('Finished')

if __name__ == '__main__': sys.exit(main())
