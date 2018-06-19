#!/usr/bin/env python2

# START COPY NOTICE
# MIT License
# Copyright (c) 2017-2018 Bozeman Pass, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# END COPY NOTICE

import sys, json, socket, argparse, os, subprocess, ldap, ldap.modlist, copy
from enum import Enum


SPECIAL_INTEROP_BUILDS = {}


class ReplicaType(Enum):
    supplier = '3'
    consumer = '2'


class DsDn(Enum):
    config = "cn=config"
    changelog = "cn=changelog5,cn=config"


class RunMode(Enum):
    PLAN = 0
    APPLY = 1


class ReplInfo(object):
    def __init__(self):
        self.role = None
        self.suffix = None
        self.replicaid = None
        self.replicapurgedelay = None
        self.init_from = None
        self.changelogdir = None
        self.changelogmaxage = None
        self.changelogcompactdbinterval = None
        self.changelogtriminterval = None
        self.repman = None


class DsEntry(object):
    def __init__(self, dn, objectClasses=None):
        self.dn = dn
        self.attrs = {}
        if objectClasses:
            self.attrs['objectClass'] = objectClasses

    def __getitem__(self, key):
        ret = self.attrs[key]
        if isinstance(ret, list) and 0 == len(ret):
            ret = ret[0]
        return ret

    def __setitem__(self, key, value):
        if isinstance(value, list):
            self.attrs[key] = value
        else:
            self.attrs[key] = [value]

    def to_add_list(self):
        return ldap.modlist.addModlist(self.attrs)


class ConfigEntry(DsEntry):
    def __init__(self, **kwargs):
        super(ConfigEntry, self).__init__(**kwargs)
        self["objectClass"] = ["top", "extensibleObject", "nsslapdConfig"]


class ReplicaEntry(DsEntry):
    def __init__(self, **kwargs):
        super(ReplicaEntry, self).__init__(**kwargs)
        self["objectClass"] = ["top", "extensibleObject", "nsds5replica"]


class ReplicationAgreementEntry(DsEntry):
    def __init__(self, **kwargs):
        super(ReplicationAgreementEntry, self).__init__(**kwargs)
        self["objectClass"] = ["top", "nsDS5ReplicationAgreement"]


class ChangeLogEntry(DsEntry):
    def __init__(self, **kwargs):
        super(ChangeLogEntry, self).__init__(**kwargs)
        self["objectClass"] = ["top", "extensibleObject"]


class InetOrgPersonEntry(DsEntry):
    def __init__(self, **kwargs):
        super(InetOrgPersonEntry, self).__init__(**kwargs)
        self["objectClass"] = ["top", "person", "inetorgperson"]


class DsHost(object):
    def __init__(self, host, port=389, binddn=None, bindpw=None, use_ssl=None):
        self.host = host
        self.port = port
        self.binddn = binddn
        self.bindpw = bindpw
        self.repl = ReplInfo()

        if use_ssl is None:
            self.use_ssl = 636 == self.port
        else:
            self.use_ssl = use_ssl

        self._version = None
        self._ldap = None

    @property
    def version(self):
        if not self._version:
            l = self.bind()
            ret = l.search_s("", ldap.SCOPE_BASE, "(objectClass=*)", ["vendorversion"])
            self._version = ret[0][1]["vendorversion"][0]
        return self._version

    def clone(self):
        ret = DsHost(self.host, port=self.port, binddn=self.binddn, bindpw=self.bindpw)
        ret.repl = copy.copy(self.repl)
        return ret

    def bind(self):
        if not self._ldap:
            scheme = "ldaps" if self.use_ssl else "ldap"
            self._ldap = ldap.initialize("%s://%s:%d" % (scheme, self.host, self.port))

            if self.binddn:
                self._ldap.simple_bind_s(self.binddn, self.bindpw)

        return self._ldap

    def search(self, base, scope=ldap.SCOPE_SUBTREE, filter="(objectClass=*)", attributes=None):
        return self.bind().search_s(base, scope, filter, attributes)

    def add(self, dn, mod_list):
        return self.bind().add_s(dn, mod_list)

    def modify(self, dn, mod_list):
        return self.bind().modify_s(dn, mod_list)

    def delete(self, dn):
        return self.bind().delete_s(dn)

    def unbind(self):
        if self._ldap and self.binddn:
            self._ldap.unbind_s()
        self._ldap = None

    def exists(self, dn):
        try:
            if self.search(dn, scope=ldap.SCOPE_BASE):
                return True
        except ldap.NO_SUCH_OBJECT:
            pass
        return False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.unbind()

    def __str__(self):
        scheme = "ldaps" if self.use_ssl else "ldap"
        return "%s://%s:%d" % (scheme, self.host, self.port)


class Task(object):
    def __init__(self, fn, msg):
        self.fn = fn
        self.msg = msg


class TargetTopo(object):
    def __init__(self):
        self.mixed_environment = False
        self.suffix = ""
        self.suppliers = []
        self.consumers = []


def log(msg, same_line=False):
    if same_line:
        sys.stdout.write(msg)
    else:
        sys.stdout.write(msg + "\n")


def warn(msg):
    sys.stderr.write(msg + "\n")


def error(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)


def normalize_suffix(s):
    if s:
        s = str(s.strip().lower().replace(" ", ""))
    return s


def make_task(msg, func, *args):
    def f(runmode):
        log("%s" % msg)
        if RunMode.APPLY is runmode:
            func(*args)

    return Task(f, msg)


def same_host(hostA, hostB):
    if hostA == hostB:
        return True

    fqA = socket.getfqdn(hostA)
    fqB = socket.getfqdn(hostB)

    if fqA == fqB:
        return True

    ipsA = []
    try:
        ipsA = set([x[4][0] for x in socket.getaddrinfo(fqA, 389, 0)])
    except:
        warn("Unable to resolve: %s" % fqA)
        ipsA = []

    ipsB = []
    try:
        ipsB = set([x[4][0] for x in socket.getaddrinfo(fqB, 389, 0)])
    except:
        warn("Unable to resolve: %s" % fqB)
        ipsB = []

    for ip in ipsA:
        if ip in ipsB:
            return True

    return False


def should_skip(ldap_host, options):
    if options.onlyfor and not same_host(ldap_host.host, options.onlyfor):
        return True

    return False


def test_for_duplicate_hosts(all_hosts):
    counted_hosts = []
    for x in all_hosts:
        for y in counted_hosts:
            if same_host(x.host, y.host):
                error("!\tDUPLICATE HOST : %s is the same as %s!" % (x, y))
        counted_hosts.append(x)


def test_for_duplicate_replicaids(all_hosts):
    rids = {}
    for x in all_hosts:
        if x.repl.replicaid:
            if x.repl.replicaid in rids:
                error("!\tDUPLICATE REPLICA ID : %s(%s) and %s(%s)" % (
                    rids[x.repl.replicaid], x.repl.replicaid, x, x.repl.replicaid))
            else:
                rids[x.repl.replicaid] = x


def get_vault_pass(hostname, key):
    cmd = "%s/get-vault-pass.sh" % options.vaulttools
    ret = subprocess.check_output([cmd, hostname, key])
    return str(ret.strip())


def parse_json_config(options, topofile):
    ret = TargetTopo()

    def get_pw(host, vault_key, local):
        if options.vaulttools:
            return str(get_vault_pass(host, vault_key))
        else:
            return str(local)

    with open(topofile, 'rt') as fp:
        parsed = json.load(fp)
        ret.suffix = normalize_suffix(parsed['suffix'])

        repman = parsed.get('repman')

        # de-unicode for python-ldap, which wants plain strings
        if repman:
            for k in repman:
                repman[k] = str(repman[k])

        for s in parsed['suppliers']:
            h = DsHost(host=str(s['hostname']),
                       port=s['port'],
                       binddn=str(s['binddn']),
                       bindpw=get_pw(s['hostname'], 'dirman', s.get('bindpw')))

            h.repl.role = ReplicaType.supplier

            h.repl.repman = s.get('repman', repman)
            if h.repl.repman:
                for k in h.repl.repman:
                    h.repl.repman[k] = str(h.repl.repman[k])
                h.repl.repman['pw'] = get_pw(s['hostname'], 'repman', h.repl.repman.get('pw'))
            else:
                error("No repman entry for %s" % s)

            h.repl.suffix = ret.suffix
            h.repl.replicaid = str(s['replicaid'])
            h.repl.replicapurgedelay = str(s.get('replicapurgedelay', 604800))
            init_from = s.get('init_from')
            if init_from:
                h.repl.init_from = str(init_from)
            h.repl.changelogdir = str(s.get('changelogdir', '/var/lib/dirsrv/slapd-%s/changelogdb' % h.host.split('.')[0]))
            h.repl.changelogmaxage = str(s.get('changelogmaxage', '7d'))
            h.repl.changelogcompactdbinterval = str(s.get('changelogcompactdbinterval', -1))
            h.repl.changelogtriminterval = str(s.get('changelogtriminterval', 300))

            ret.suppliers.append(h)

        if 'consumers' in parsed:
            for c in parsed['consumers']:
                h = DsHost(host=str(c['hostname']),
                           port=c['port'],
                           binddn=str(c['binddn']),
                           bindpw=get_pw(c['hostname'], 'dirman', s.get('bindpw')))

                h.repl.role = ReplicaType.consumer
                h.repl.suffix = ret.suffix
                h.repl.init_from = str(c['init_from'])

                h.repl.repman = c.get('repman', repman)
                if h.repl.repman:
                    for k in h.repl.repman:
                        h.repl.repman[k] = str(h.repl.repman[k])
                    h.repl.repman['pw'] = get_pw(s['hostname'], 'repman', h.repl.repman.get('pw'))
                else:
                    error("No repman entry for %s" % c)

                ret.consumers.append(h)

    return ret


def add_repman(ldap_host):
    entry = InetOrgPersonEntry(dn=ldap_host.repl.repman['dn'])
    entry['sn'] = 'repman'
    entry['userPassword'] = ldap_host.repl.repman['pw']

    ldap_host.add(entry.dn, entry.to_add_list())


def create_changelog(ldap_host):
    entry = ChangeLogEntry(dn=DsDn.changelog.value)
    entry['nsslapd-changelogdir'] = ldap_host.repl.changelogdir
    entry['nsslapd-changelogmaxage'] = ldap_host.repl.changelogmaxage
    entry['nsslapd-changelogcompactdb-interval'] = ldap_host.repl.changelogcompactdbinterval
    entry['nsslapd-changelogtrim-interval'] = ldap_host.repl.changelogtriminterval

    ldap_host.add(entry.dn, entry.to_add_list())


def create_replica(ldap_host):
    dn = 'cn=replica,cn="%s",cn=mapping tree,cn=config' % (ldap_host.repl.suffix)

    entry = ReplicaEntry(dn=dn)
    entry['nsds5replicaroot'] = ldap_host.repl.suffix
    entry['nsds5replicatype'] = ldap_host.repl.role.value
    entry['nsds5ReplicaBindDN'] = ldap_host.repl.repman['dn']

    if ReplicaType.supplier is ldap_host.repl.role:
        entry['nsds5replicaid'] = ldap_host.repl.replicaid
        entry['nsds5flags'] = '1'
    elif ReplicaType.consumer is ldap_host.repl.role:
        entry['nsds5replicaid'] = '65535'
        entry['nsds5flags'] = '0'

    ldap_host.add(entry.dn, entry.to_add_list())


def create_repl_agreement(supplier, consumer):
    shortS = supplier.host.split(".")[0]
    shortC = consumer.host.split(".")[0]

    transport = 'LDAP'
    if 636 == consumer.port:
        transport = 'SSL'

    dn = 'cn=%s_to_%s,cn=replica,cn="%s",cn=mapping tree,cn=config' % (shortS, shortC, consumer.repl.suffix)

    ra = ReplicationAgreementEntry(dn=dn)
    ra['nsDS5ReplicaHost'] = consumer.host
    ra['nsDS5ReplicaRoot'] = consumer.repl.suffix
    ra['nsDS5ReplicaPort'] = str(consumer.port)
    ra['nsDS5ReplicaTransportInfo'] = transport
    ra['nsDS5ReplicaBindDN'] = consumer.repl.repman['dn']
    ra['nsDS5ReplicaBindMethod'] = 'simple'
    ra['nsDS5ReplicaCredentials'] = consumer.repl.repman['pw']
    ra['nsDS5ReplicaTimeOut'] = '120'

    if supplier.version in SPECIAL_INTEROP_BUILDS:
        if 'Fedora-Directory/1.1' in consumer.version:
            ra['nsds5ReplicaDisableSchemaRepl'] = '1'

    supplier.add(ra.dn, ra.to_add_list())


def initialize_consumer(supplier, consumer):
    agreement_dn = None
    agreements = supplier.search(DsDn.config.value, filter='(objectclass=nsDS5ReplicationAgreement)')
    for dn, entry in agreements:
        if supplier.repl.suffix == normalize_suffix(entry['nsDS5ReplicaRoot'][0]):
            if same_host(consumer.host, entry['nsDS5ReplicaHost'][0]):
                agreement_dn = dn
                break

    mod_list = [(ldap.MOD_REPLACE, 'nsds5beginreplicarefresh', ['start'])]
    supplier.modify(agreement_dn, mod_list)


def disable_schema_mod(ldap_host):
    mod_list = [(ldap.MOD_REPLACE, 'nsslapd-schemamod', ['off']),
                (ldap.MOD_REPLACE, 'nsslapd-schemamod-refuse-result-code', ['19'])]
    ldap_host.modify(DsDn.config.value, mod_list)


def remove_repl_agreement(supplier, agreement_dn):
    supplier.delete(agreement_dn)


def basic_repl_tasks(ldap_host, options):
    ret = []

    repman_dn = ldap_host.repl.repman['dn']
    repman_pw = ldap_host.repl.repman['pw']

    # check whether it has repman
    if not ldap_host.exists(repman_dn):
        ret.append(make_task("+\t%s : add_repman" % ldap_host, add_repman, ldap_host))
    else:
        rl = ldap_host.clone()
        rl.binddn = repman_dn
        rl.bindpw = repman_pw
        with rl:
            try:
                rl.bind()
                if options.verbose:
                    log("=\t%s : add_repman" % ldap_host)
            except:
                warn("!\t%s : %s exists, but cannot bind" % (ldap_host, repman_dn))

    # check whether is has a changelog
    if not ldap_host.exists(DsDn.changelog.value):
        if ReplicaType.supplier is ldap_host.repl.role:
            ret.append(make_task("+\t%s : create_changelog" % ldap_host, create_changelog, ldap_host))
        elif options.verbose and ReplicaType.consumer is not ldap_host.repl.role:
            log("=\t%s : create_changelog" % ldap_host)
    elif ReplicaType.consumer is ldap_host.repl.role:
        warn("!\t%s : changelog should not exist on a consumer" % ldap_host)

    # check whether it has a replica
    replica_entries = ldap_host.search('cn=mapping tree,cn=config', filter='(objectClass=nsds5replica)',
                                       attributes=['nsds5replicaroot', 'nsds5replicaid', 'nsds5replicatype',
                                                   'nsds5flags'])
    suffixes = [normalize_suffix(entry['nsds5replicaroot'][0]) for dn, entry in replica_entries]
    if ldap_host.repl.suffix not in suffixes:
        ret.append(make_task("+\t%s : create_replica" % ldap_host, create_replica, ldap_host))
    else:
        matched = True
        for dn, entry in replica_entries:
            if ldap_host.repl.suffix == normalize_suffix(entry['nsds5replicaroot'][0]):
                erid = entry['nsds5replicaid'][0]
                if erid != str(ldap_host.repl.replicaid):
                    if '65535' != erid or ldap_host.repl.role is not ReplicaType.consumer:
                        matched = False
                        warn("!\t%s : replicaid %s does not match %s" % (ldap_host, erid, ldap_host.repl.replicaid))

                etype = entry['nsds5replicatype'][0]
                if etype != ldap_host.repl.role.value:
                    matched = False
                    warn("!\t%s : replicatype %s does not match %s" % (ldap_host, etype, ldap_host.repl.role.value))

                rflags = "1" if ldap_host.repl.role is ReplicaType.supplier else "0"
                eflags = entry['nsds5flags'][0]

                if eflags != rflags:
                    matched = False
                    warn("!\t%s : flags %s does not match %s" % (ldap_host, eflags, rflags))

        if matched:
            if options.verbose:
                log("=\t%s : create_replica" % ldap_host)

    return ret


def replform(options):
    topo = parse_json_config(options, options.cfgfile)

    tasks = []
    all_hosts = []
    all_hosts.extend(topo.suppliers)
    all_hosts.extend(topo.consumers)

    test_for_duplicate_hosts(all_hosts)
    test_for_duplicate_replicaids(topo.suppliers)

    examine_suppliers = [x for x in topo.suppliers if not should_skip(x, options)]
    examine_consumers = [x for x in topo.consumers if not should_skip(x, options)]
    examine_all = [x for x in all_hosts if not should_skip(x, options)]

    should_disable_schemamod = False

    # we really need to check all the hosts here,
    # even if we are only willing to change us, since
    # we need to know if this is a mixed cluster
    for host in all_hosts:
        if 'Fedora-Directory/1.1' in host.version:
            should_disable_schemamod = True
            break

    # if we need to disable schema modifications, do that before configuring replication
    if should_disable_schemamod:
        for host in examine_all:
            if host.version in SPECIAL_INTEROP_BUILDS:
                found = False
                dn, entry = host.search(DsDn.config.value, attributes=['nsslapd-schemamod',
                                                                       'nsslapd-schemamod-refuse-result-code'])[0]
                if 'nsslapd-schemamod' in entry:
                    if 'off' in entry['nsslapd-schemamod']:
                        if 'nsslapd-schemamod-refuse-result-code' in entry:
                            if '19' in entry['nsslapd-schemamod-refuse-result-code']:
                                found = True

                if not found:
                    tasks.append(make_task("+\t%s : disable_schema_mod" % host, disable_schema_mod, host))
                elif options.verbose:
                    log("=\t%s : disable_schema_mod" % host)

    # do the basic supplier tasks first
    for supplier in examine_suppliers:
        tasks.extend(basic_repl_tasks(supplier, options))

    # then the basic consumer tasks
    for consumer in examine_consumers:
        tasks.extend(basic_repl_tasks(consumer, options))
        agreements = consumer.search(DsDn.config.value, filter='(objectclass=nsDS5ReplicationAgreement)')
        for dn, entry in agreements:
            warn("!\t%s : replication agreement should not exist on a consumer -> %s" % (
                consumer, entry['nsDS5ReplicaHost'][0]))

    # then the replication agreements on the suppliers
    for supplier in examine_suppliers:
        agreements = supplier.search(DsDn.config.value, filter='(objectclass=nsDS5ReplicationAgreement)')

        # first check for existing agreements that match no known host
        for dn, entry in agreements:
            if supplier.repl.suffix == normalize_suffix(entry['nsDS5ReplicaRoot'][0]):
                rhost = entry['nsDS5ReplicaHost'][0]

                missing = True
                for host in all_hosts:
                    if same_host(host.host, rhost):
                        missing = False
                        break

                if missing:
                    if options.doremove:
                        tasks.append(make_task("-\t%s : remove_repl_agreement -> %s" % (supplier, rhost),
                                               remove_repl_agreement, supplier, dn))
                    else:
                        warn("!\t%s : unknown replication agreement -> %s" % (supplier, rhost))

        # now look for what agreements to add to fill out the topology
        for consumer in all_hosts:
            if same_host(consumer.host, supplier.host): continue

            found = False
            found_entry = None
            for dn, entry in agreements:
                if supplier.repl.suffix == normalize_suffix(entry['nsDS5ReplicaRoot'][0]):
                    rhost = entry['nsDS5ReplicaHost'][0]
                    if same_host(consumer.host, rhost):
                        found = True
                        found_entry = entry
                        break

            if not found:
                tasks.append(make_task("+\t%s : create_repl_agreement -> %s" % (supplier, consumer),
                                       create_repl_agreement, supplier, consumer))
            elif options.verbose:
                log("=\t%s : create_repl_agreement -> %s" % (supplier, consumer))

            if found and found_entry.get('nsds5BeginReplicaRefresh'):
                warn("!\t%s : initialization in progress -> %s" % (supplier, consumer))
            else:
                # comparing the replica generation of the supplier and consumer will tell us if the consumer
                # has been initialized into this cluster (by whatever initialization method)
                if consumer.repl.init_from and same_host(supplier.host, consumer.repl.init_from):
                    found = False
                    try:
                        res_sup = supplier.search(supplier.repl.suffix,
                                                  filter='(&(nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff)(objectclass=nstombstone))')
                        res_con = consumer.search(consumer.repl.suffix,
                                                  filter='(&(nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff)(objectclass=nstombstone))')
                        if res_sup and res_con:
                            _, supplier_tombstone = res_sup[0]
                            _, consumer_tombstone = res_con[0]
                            for sruv in supplier_tombstone.get('nsds50ruv', []):
                                if '{replicageneration}' in sruv:
                                    for cruv in consumer_tombstone.get('nsds50ruv', []):
                                        if '{replicageneration}' in cruv:
                                            if sruv == cruv:
                                                found = True
                    except Exception, e:
                        found = None

                    if not found:
                        if found is False:
                            if options.doinit:
                                tasks.append(
                                    make_task("+\t%s : initialize_consumer -> %s" % (supplier, consumer),
                                              initialize_consumer,
                                              supplier, consumer))
                            else:
                                warn("!\t%s : uninitialized -> %s " % (supplier, consumer))
                        elif found is None:
                            warn("!\t%s : unable to determine initialization status -> %s " % (supplier, consumer))
                    elif options.verbose:
                        log("=\t%s : initialize_consumer -> %s" % (supplier, consumer))

    # run the tasks
    for task in tasks:
        task.fn(options.runmode)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='replform.py <plan | apply>',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f', '--config-file', type=str, default='replform.rf', dest='cfgfile',
                        help='Configuration file.  Default replform.rf')

    parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose',
                        help='Verbose output')

    parser.add_argument('--initialize', action='store_true', default=False, dest='doinit',
                        help='Initialize replicas.')

    parser.add_argument('--remove-missing', action='store_true', default=False, dest='doremove',
                        help='Remove agreements to missing servers.')

    parser.add_argument('--only-for', type=str, dest='onlyfor',
                        help='Examine the specified host.  Default is the current host.')

    parser.add_argument('-g', '--global', action='store_true', default=False, dest='xglobal',
                        help='Examine all servers.  Default is the current host.')

    parser.add_argument('--vault-tools-dir', type=str, default=None, dest='vaulttools',
                        help='Vault tools directory.  If set, uses Vault for all passwords.')


    def usage():
        error("Usage:\n"
              "\treplform.py plan [options ...]\n"
              "\treplform.py apply [options ...]")


    if len(sys.argv) > 1:
        if "plan" == sys.argv[1]:
            mode = RunMode.PLAN
        elif "apply" == sys.argv[1]:
            mode = RunMode.APPLY
        else:
            usage()
    else:
        usage()

    options = parser.parse_args(sys.argv[2:])
    options.runmode = mode

    if not os.path.exists(options.cfgfile):
        error("%s does not exist!" % options.cfgfile)

    if options.onlyfor:
        options.xglobal = False
    elif not options.xglobal:
        options.onlyfor = socket.gethostname()

    log("%s: %s" % (options.runmode.name, options.onlyfor if options.onlyfor else 'global'))

    replform(options)
