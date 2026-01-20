#!/usr/local/bin/python3

"""
    Copyright (c) 2022-2023 Ad Schellevis <ad@opnsense.org>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    --------------------------------------------------------------------------------------
    handle swanctl.conf updown event
"""
import os
import subprocess
import argparse
import syslog
from configparser import ConfigParser
from lib import list_spds

events_filename = '/usr/local/etc/swanctl/reqid_events.conf'

spd_add_cmd = 'spdadd -%(ipproto)s %(source)s %(destination)s any ' \
    '-P out ipsec %(protocol)s/tunnel/%(local)s-%(remote)s/unique:%(reqid)s;'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--connection_child', help='uuid of the connection child')
    parser.add_argument('--reqid', default=os.environ.get('PLUTO_REQID'))
    parser.add_argument('--local', default=os.environ.get('PLUTO_ME'))
    parser.add_argument('--remote', default=os.environ.get('PLUTO_PEER'))
    parser.add_argument('--action', default=os.environ.get('PLUTO_VERB'))
    cmd_args = parser.parse_args()
    # init spd's on up-host[-v6], up-client[-v6]
    if cmd_args.action and cmd_args.action.startswith('up'):
        syslog.openlog('charon', facility=syslog.LOG_LOCAL4)
        syslog.syslog(syslog.LOG_NOTICE, '[UPDOWN] <%s> received %s event for reqid %s' % (cmd_args.connection_child, cmd_args.action, cmd_args.reqid))
        if os.path.exists(events_filename):
            ipproto, host_suffix = ('4', '/32') if cmd_args.action[-1] != '6' else ('6', '/128')
            cnf = ConfigParser()
            cnf.read(events_filename)
            spds = []
            spd_set = set() # tuple(source, destination)
            with_vti = False
            for section, options in cnf.items():
                if (options.get('reqid', '') == cmd_args.reqid or
                    options.get('connection_child', '') == cmd_args.connection_child
                ):
                    if section.startswith('spd_'):
                        # remove prefix length in case of host (setkey returns host only)
                        source = options.get('source', '').strip().removesuffix(host_suffix)
                        # continue only if ipproto matches spd in conf to up-event
                        if (ipproto == '6') == (':' in source):
                            destination = options.get('destination', '').strip()
                            if destination == '':
                                destination = os.environ.get('PLUTO_PEER_CLIENT', '')
                            destination = destination.removesuffix(host_suffix)
                            spds.append({
                                'ipproto': ipproto,
                                'source': source,
                                'reqid': cmd_args.reqid,
                                'local' : cmd_args.local,
                                'remote' : cmd_args.remote,
                                'destination': destination,
                                'protocol': options.get('protocol', '').strip()
                            })
                            spd_set.add((source, destination))
                    elif section.startswith('vti_'):
                        with_vti = True

            if with_vti:
                intf = 'ipsec%s' % cmd_args.reqid
                proto = 'inet6' if ipproto == '6' else 'inet'
                subprocess.run(['/sbin/ifconfig', intf, 'reqid', cmd_args.reqid])
                subprocess.run(['/sbin/ifconfig', intf, proto, 'tunnel', cmd_args.local, cmd_args.remote])

            # (re)apply manual policies if specified
            cur_spds = list_spds(automatic=False)
            set_key = [] # list of setkey actions to run
            for spd in cur_spds:
                # match requid only if ipproto matches
                reqid_match = spd['reqid'] == cmd_args.reqid and (ipproto == '6') == (':' in spd['src'])
                if reqid_match or (spd['src'], spd['dst']) in spd_set:
                    spd_del_cmd = 'spddelete -n %(src)s %(dst)s any -P %(direction)s;' % spd
                    set_key.append(spd_del_cmd)
                    reason = 'reqid match' if reqid_match else 'policy found'
                    syslog.syslog(
                        syslog.LOG_NOTICE,
                        '[UPDOWN] <%s> delete policy: %s (reason: %s)' % (cmd_args.connection_child, spd_del_cmd[10:], reason)
                    )

            for spd in spds:
                if None in spd.values():
                    # incomplete, skip
                    continue
                syslog.syslog(
                    syslog.LOG_NOTICE,
                    '[UPDOWN] <%s> add manual policy: %s' % (cmd_args.connection_child, (spd_add_cmd % spd)[7:])
                )
                set_key.append(spd_add_cmd % spd)
            if len(set_key) > 0:
                try:
                    subprocess.run(['/sbin/setkey', '-c'], input='\n'.join(set_key), capture_output=True, text=True, check=True)
                except subprocess.CalledProcessError as e:
                    syslog.syslog(
                        syslog.LOG_ERR,
                        '[UPDOWN] <%s> setkey failed: stdout: (%s) stderr: (%s)' % (cmd_args.connection_child, e.stdout, e.stderr)
                    )
