# -*- coding: utf-8 -*-
#
# tc-control.py
#
# Author:   Toke Høiland-Jørgensen (toke@toke.dk)
# Date:     23 May 2018
# Copyright (c) 2018, Toke Høiland-Jørgensen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import subprocess
import ipaddress
import sys
import os

BPFTOOL = os.getenv("BPFTOOL", "bpftool")
MAP_NAME = os.getenv("MAP_NAME", "/sys/fs/bpf/tc/globals/subnets")


def run_bpftool(command, action, args=[]):
    proc = subprocess.Popen([BPFTOOL, command, "-j",
                             action, "pinned", MAP_NAME] + list(args),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = proc.communicate()

    if proc.returncode != 0:
        err = json.loads(out)
        raise RuntimeError(err['error'])

    return out


def map_dump():
    data = json.loads(run_bpftool("map", "dump"))
    for d in data:
        key = [int(k, 16) for k in d['key']]
        value = [int(v, 16) for v in d['value']]
        mask = key[0]
        ipa = key[7] + (key[6] << 8) + (key[5] << 16) + (key[4] << 24)
        net = ipaddress.IPv4Network((ipa, mask))
        cls = value[0] + (value[1] << 8)
        yield net, cls


def get_key(net):
    nd = net.network_address.packed
    return [net.prefixlen, 0, 0, 0, nd[0], nd[1], nd[2], nd[3]]


def map_update(net, cls):
    net = ipaddress.IPv4Network(net)
    key = get_key(net)
    cls = int(cls)
    if not 0 < cls <= 1024:
        raise RuntimeError("Class must be > 0 and < 1024")
    value = [(cls & 0xff), ((cls >> 8) & 0xff)]

    args = ['key'] + [str(i) for i in key]
    args += ['value'] + [str(i) for i in value]
    run_bpftool('map', 'update', args)


def do_delete(net):
    key = get_key(net)
    args = ['key'] + [str(i) for i in key]
    run_bpftool('map', 'delete', args)


def map_delete(net):
    if net == 'all':
        for net, cls in map_dump():
            do_delete(net)
    else:
        do_delete(ipaddress.IPv4Network(net))


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            if sys.argv[1] == '-d':
                map_delete(sys.argv[2])
            elif sys.argv[1] == '-f':
                with open(sys.argv[2]) as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        map_update(*line.split()[:2])
            elif sys.argv[1] == '-h':
                print("Usage: {} [<net> <class> | "
                      "-d <net> | -f <filename>]".format(sys.argv[0]),
                      file=sys.stderr)
                sys.exit(0)
            else:
                map_update(sys.argv[1], sys.argv[2])

        for net, cls in map_dump():
            print(net, cls)
    except KeyboardInterrupt:
        pass
    except ipaddress.AddressValueError:
        print("Invalid IP subnet", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
