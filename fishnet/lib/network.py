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

from pex.net import Net

from django.db.models import QuerySet

from fishnet.apps.home.models import Network as NetworkDB
from fishnet.apps.home.models import Host as HostDB
from fishnet.apps.home.models import Flaw as FlawDB
from fishnet.apps.home.models import Session as SessionDB

from fishnet.lib.plugins import Plugins
from fishnet.lib.projects import Projects


class Network:
    """ Subclass of fishnet.lib module.

    This subclass of fishnet.lib module is intended for providing
    an implementation of native network scanner.
    """

    net = Net()

    plugins = Plugins()
    projects = Projects()

    scanners = sort(plugins.load_plugins('network'))

    scanner = threading.Thread()
    jobs = {}
    job = {}

    def stop_scan(self, project_uuid: str) -> None:
        """ Stop network scanner.

        :param str project_uuid: project UUID
        :return None: None
        """

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

    def start_scan(self, project_uuid: str, scanners: list, gateway: str = '') -> None:
        """ Start network scanner.

        :param str project_uuid: project UUID
        :param list scanners: list of scanners to execute
        :param str gateway: custom gateway (or bunch of them)
        :return None: None
        """

        local_gateways = self.net.get_gateways()

        if gateway:
            gateways = {}
            number = 0

            for iface in local_gateways:
                if local_gateways[iface] in gateway.split():
                    gateways.update({iface: local_gateways[iface]})

            for gtw in gateway.split():
                if gtw not in gateways.values():
                    gateways.update({f'fnet{str(number)}': gtw})
                    number += 1
        else:
            gateways = local_gateways

        if isinstance(scanners, str):
            scanners = [scanners]

        if project_uuid not in self.jobs:
            self.jobs[project_uuid] = {}

        for scanner in scanners:
            if scanner in self.scanners:
                if scanner not in self.jobs[project_uuid]:
                    self.jobs[project_uuid][scanner] = {}

                for iface in gateways:
                    if iface == 'lo0':
                        continue

                    if iface not in self.jobs[project_uuid][scanner]:
                        self.jobs[project_uuid][scanner][iface] = threading.Thread(
                            target=self.scanners[scanner]['plugin'].run,
                            args=[{
                                'gateway': gateways[iface],
                                'iface': iface,
                                'method': 'arp' if iface in local_gateways else 'icmp',
                                'project_uuid': project_uuid
                            }]
                        )
                        self.jobs[project_uuid][scanner][iface].setDaemon(True)
                        self.jobs[project_uuid][scanner][iface].start()

                        while True:
                            if iface in [network.iface for network in NetworkDB.objects.filter(project=project_uuid)]:
                                break

    def run_attack(self, project_uuid: str, flaw: str, options: dict) -> str:
        """ Run attack using scanner which has the feature to attack.

        :param str project_uuid: project UUID
        :param str flaw: flaw name
        :param dict options: options to set in scanner
        :return str: attack log
        """

        flaws = FlawDB.objects.filter(project=project_uuid)
        flaw_object = flaws.get(name=flaw)

        if hasattr(self.scanners[flaw_object.plugin]['plugin'], 'attack'):
            return self.scanners[flaw_object.plugin]['plugin'].attack(flaw, options)
        return ''

    def session_execute(self, project_uuid: str, session: int, command: str) -> str:
        """ Execute command on session.

        :param str project_uuid: project UUID
        :param int session: session to execute command on
        :param str command: command to execute on session
        :return str: command output
        """

        sessions = SessionDB.objects.filter(project=project_uuid)
        session_object = sessions.get(session=session)

        if hasattr(self.scanners[session_object.plugin]['plugin'], 'get_session'):
            try:
                return self.scanners[session_object.plugin]['plugin'].get_session(
                    session
                ).send_command(command, True)
            except Exception:
                pass
        return ''

    def close_session(self, project_uuid: str, session: int) -> None:
        """ Close session.

        :param str project_uuid: project UUID
        :param int session: session to close
        :return None: None
        """

        sessions = SessionDB.objects.filter(project=project_uuid)
        session_object = sessions.get(session=session)

        if hasattr(self.scanners[session_object.plugin]['plugin'], 'close_session'):
            try:
                self.scanners[session_object.plugin]['plugin'].close_session(session)
            except Exception:
                pass

    def run_scan(self, project_uuid: str, scanners: list, gateway: str = '') -> None:
        """ Run network scanner (thread mode).

        :param str project_uuid: project UUID
        :param str scanners: list of scanners to execute
        :param str gateway: custom gateway
        :return None: None
        """

        self.job[project_uuid] = threading.Thread(target=self.start_scan, args=[
            project_uuid,
            scanners,
            gateway
        ])
        self.job[project_uuid].setDaemon(True)
        self.job[project_uuid].start()

    def get_details(self, project_uuid, host) -> dict:
        """ Get host details.

        :param str project_uuid: project UUID
        :param str host: host to get details for
        :return dict: host details
        """

        hosts = HostDB.objects.filter(project=project_uuid)
        host = hosts.get(host=host)

        flaws = FlawDB.objects.filter(project=project_uuid)
        flaws = flaws.filter(host=host.host)

        flaws_ranks = {}

        for flaw in flaws:
            if flaw.rank not in flaws_ranks:
                flaws_ranks[flaw.rank] = 0
            flaws_ranks[flaw.rank] += 1

        sessions = self.get_sessions(project_uuid).filter(host=host.host)

        sessions_types = {}

        for session in sessions:
            if session.platform not in sessions_types:
                sessions_types[session.type] = 0
            sessions_types[session.type] += 1

        return {
            'host': host.host,
            'platform': host.platform,
            'mac': host.mac,
            'vendor': host.vendor,
            'dns': host.dns,
            'gateway': host.gateway,
            'flaws': flaws,
            'flaws_ranks': [list(flaws_ranks.keys()), list(flaws_ranks.values())],
            'sessions': sessions,
            'sessions_types': [list(sessions_types.keys()), list(sessions_types.values())]
        }

    def get_sessions(self, project_uuid: str) -> QuerySet:
        """ Get sessions available for project.

        NOTE: Sessions are objects that contain an image of TCP connection
        with target that has been attacked. Sessions can be closed, manipulated,
        you can send commands to it, download/upload files.

        :param str project_uuid: project UUID
        :return QuerySet: sessions available for project
        """

        for scanner in self.scanners:
            if hasattr(self.scanners[scanner]['plugin'], 'sessions'):
                self.scanners[scanner]['plugin'].sessions(project_uuid)

        return SessionDB.objects.filter(project=project_uuid)

    def get_scan(self, project_uuid: str) -> dict:
        """ Get all data available for project.

        :param str project_uuid: project UUID
        :return dict: all data available for project
        """

        networks = NetworkDB.objects.filter(project=project_uuid)
        hosts = HostDB.objects.filter(project=project_uuid)
        flaws = FlawDB.objects.filter(project=project_uuid)
        sessions = self.get_sessions(project_uuid)

        platforms = {}
        services = {}
        flaws_ranks = {}

        session_platforms = {}

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

        for session in sessions:
            if session.platform not in session_platforms:
                session_platforms[session.platform] = 0
            session_platforms[session.platform] += 1

        return {
            'animate': True,
            'scanners': self.scanners.items(),

            'networks': networks,
            'hosts': hosts,
            'flaws': flaws,
            'sessions': sessions,

            'services': [list(services.keys()), list(services.values())],
            'platforms': [list(platforms.keys()), list(platforms.values())],
            'session_platforms': [list(session_platforms.keys()), list(session_platforms.values())],
            'flaws_ranks': [list(flaws_ranks.keys()), list(flaws_ranks.values())]
        }
