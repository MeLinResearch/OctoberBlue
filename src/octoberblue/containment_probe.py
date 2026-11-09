"""Fixed controlled diagnostic, not a general code execution endpoint."""
import json
import os
import socket
import sys
from pathlib import Path


def main():
    request = json.loads(sys.stdin.buffer.read(8193))
    if type(request) is not dict or set(request) != {"host_sentinel", "memory_limit", "cpu_limit"}:
        return 2
    if type(request["host_sentinel"]) is not str or len(request["host_sentinel"]) > 4096:
        return 2
    if (type(request["memory_limit"]) is not int or request["memory_limit"] <= 0
            or type(request["cpu_limit"]) not in (int, float)
            or not 0 < request["cpu_limit"] <= 1):
        return 2
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
    root_options = next(row[3].split(',') for row in mounts if row[1] == '/')
    tmp_options = next(row[3].split(',') for row in mounts if row[1] == '/tmp')
    sock = socket.socket()
    sock.settimeout(0.2)
    try:
        sock.connect(('198.51.100.1', 9))  # Documentation-only TEST-NET address.
        outbound_blocked = False
    except OSError:
        outbound_blocked = True
    finally:
        sock.close()
    def limited(name, maximum):
        try:
            value = Path('/sys/fs/cgroup/' + name).read_text().strip()
            return value != 'max' and 0 < int(value) <= maximum
        except (OSError, ValueError):
            return False

    try:
        quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
        cpu_limited = quota != 'max' and 0 < int(quota) / int(period) <= request['cpu_limit']
    except (OSError, ValueError, ZeroDivisionError):
        cpu_limited = False
    report = {
        'memory_limit_enforced': limited('memory.max', request['memory_limit']),
        'pids_limit_enforced': limited('pids.max', 32),
        'cpu_limit_enforced': cpu_limited,
        'non_root': os.geteuid() == 65534,
        'read_only_root': 'ro' in root_options,
        'no_new_privileges': status.get('NoNewPrivs', '').strip() == '1',
        'no_effective_capabilities': int(status.get('CapEff', '1').strip(), 16) == 0,
        'private_tmp_noexec': 'noexec' in tmp_options and 'nosuid' in tmp_options,
        'outbound_blocked': outbound_blocked,
        'host_sentinel_hidden': not Path(request['host_sentinel']).exists(),
        'docker_socket_hidden': not Path('/var/run/docker.sock').exists(),
        'ambient_secret_absent': 'OCTOBERBLUE_CONTAINMENT_SECRET' not in os.environ,
    }
    sys.stdout.write(json.dumps(report, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
