"""
MIT License

Copyright (c) 2020-2022 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import ctypes
import threading

from fishnet.apps.home.models import Network as NetworkDB
from fishnet.apps.home.models import Host as HostDB
from fishnet.apps.home.models import Flaw as FlawDB

from fishnet.lib.plugins import Plugins
from fishnet.lib.projects import Projects


class Network:
    plugins = Plugins()
    projects = Projects()

    scanners = plugins.load_plugins('network')

    scanner = threading.Thread()
    jobs = {}
    job = threading.Thread()

    def stop_scan(self, project_uuid):
        if project_uuid in self.jobs:
            for scanner in list(self.jobs[project_uuid]):
                for iface in list(self.jobs[project_uuid][scanner]):
                    job = self.jobs[project_uuid][scanner][iface]

                    if job.is_alive():
                        exc = ctypes.py_object(SystemExit)
                        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(job.ident), exc)

                        if res > 1:
                            ctypes.pythonapi.PyThreadState_SetAsyncExc(job.ident, None)
                            return

                self.jobs[project_uuid].pop(scanner)
            self.jobs.pop(project_uuid)

    def start_scan(self, project_uuid, scanners):
        gateways = self.net.get_gateways()

        if isinstance(scanners, str):
            scanners = [scanners]

        if project_uuid not in self.jobs:
            self.jobs[project_uuid] = {}

        for scanner in scanners:
            if scanner in self.scanners:
                if scanner not in self.jobs[project_uuid]:
                    self.jobs[project_uuid][scanner] = {}

                for iface in gateways:
                    if iface not in self.jobs[project_uuid][scanner]:
                        self.jobs[project_uuid][scanner][iface] = threading.Thread(
                            target=self.scanners[scanner]['plugin'].run,
                            args=[{
                                'gateway': gateways[iface],
                                'iface': iface,
                                'project_uuid': project_uuid
                            }]
                        )
                        self.jobs[project_uuid][scanner][iface].setDaemon(True)
                        self.jobs[project_uuid][scanner][iface].start()
                        self.jobs[project_uuid][scanner][iface].join()

    def run_scan(self, project_uuid, scanners):
        self.job[project_uuid] = threading.Thread(target=self.start_scan, args=[
            project_uuid,
            scanners
        ])
        self.job[project_uuid].setDaemon(True)
        self.job[project_uuid].start()

    def get_scan(self, project_uuid):
        networks = NetworkDB.objects.filter(project=project_uuid)
        hosts = HostDB.objects.filter(project=project_uuid)
        flaws = FlawDB.objects.filter(project=project_uuid)

        platforms = {}
        services = {}
        flaws_ranks = {}

        for host in hosts:
            for port in host.ports:
                if host.ports[port] not in services:
                    services[host.ports[port]] = 0
                services[host.ports[port]] += 1

            if host.platform not in platforms:
                platforms[host.platform] = 0
            platforms[host.platform] += 1

        for flaw in flaws:
            if flaw.rank not in flaws_ranks:
                flaws_ranks[flaw.rank] = 0
            flaws_ranks[flaw.rank] += 1

        return {
            'animate': True,
            'scanners': self.scanners.items(),
            'networks': networks,
            'hosts': hosts,
            'flaws': flaws,
            'services': [list(services.keys()), list(services.values())],
            'platforms': [list(platforms.keys()), list(platforms.values())],
            'flaws_ranks': [list(flaws_ranks.keys()), list(flaws_ranks.values())]
        }
