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
import uuid
import ctypes
import random
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

    scanners = dict(
        sorted(plugins.load_plugins('network').items())
    )

    download_queue = {}
    download_threads = {}

    upload_queue = {}
    upload_threads = {}

    scanner = threading.Thread()

    jobs = {}
    job = {}

    colors = [
        "#dc3545",
        "#fd7e14",
        "#ffc107",
        "#198754",
        "#20c997",
        "#0d6efd",
        "#0dcaf0"
    ]

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

    def start_scan(self, project_uuid: str, scanners: list, gateway: str = '', cycle: bool = True) -> None:
        """ Start network scanner.

        :param str project_uuid: project UUID
        :param list scanners: list of scanners to execute
        :param str gateway: custom gateway (or bunch of them)
        :param bool cycle: cyclic scanning through selected scanners
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
                            target=self.scan_thread,
                            args=[
                                project_uuid,
                                scanner,
                                gateways[iface],
                                iface,
                                'arp' if iface in local_gateways else 'icmp',
                                cycle
                            ]
                        )
                        self.jobs[project_uuid][scanner][iface].setDaemon(True)
                        self.jobs[project_uuid][scanner][iface].start()

                        while True:
                            if iface in [network.iface for network in NetworkDB.objects.filter(project=project_uuid)]:
                                break

    def scan_thread(self, project_uuid: str, scanner: str, gateway: str,
                    iface: str, method: str, cycle: bool) -> None:
        """ Scanner thread target function.

        :param str project_uuid: project UUID
        :param str scanner: scanner to use
        :param str gateway: gateway to scan
        :param str iface: interface to scan
        :param str method: scan method (arp/icmp)
        :param bool cycle: cyclic scanning through selected scanners
        :return None: None
        """

        if cycle:
            while True:
                self.scanners[scanner]['plugin'].run({
                    'gateway': gateway,
                    'iface': iface,
                    'method': method,
                    'project_uuid': project_uuid
                })
        else:
            self.scanners[scanner]['plugin'].run({
                'gateway': gateway,
                'iface': iface,
                'method': method,
                'project_uuid': project_uuid
            })

    def set_option(self, project_uuid: str, flaw: str, option: str, value: str) -> None:
        """ Set flaw option value.

        :param str project_uuid: project UUID
        :param str flaw: flaw name
        :param str option: option to set
        :param str value: value
        :return None: None
        """

        flaws = FlawDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        if flaws.filter(name=flaw).exists():
            flaw_object = flaws.get(name=flaw)

            if flaw_object.exploitable:
                if flaw_object.plugin in plugins:
                    if hasattr(self.scanners[flaw_object.plugin]['plugin'], 'set'):
                        self.scanners[flaw_object.plugin]['plugin'].set(flaw, option, value)
        else:
            for scanner in self.scanners:
                if scanner in plugins:
                    if hasattr(self.scanners[scanner]['plugin'], 'set'):
                        self.scanners[scanner]['plugin'].set(flaw, option, value)
                        break

    def get_payloads(self, project_uuid: str, flaw: str) -> list:
        """ Get all flaw payloads.

        :param str project_uuid: project UUID
        :param str flaw: flaw to get payloads for
        :return list: all payloads
        """

        flaws = FlawDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        payloads = []

        if flaws.filter(name=flaw).exists():
            flaw_object = flaws.get(name=flaw)

            if flaw_object.exploitable:
                if flaw_object.plugin in plugins:
                    if hasattr(self.scanners[flaw_object.plugin]['plugin'], 'payloads'):
                        payloads += self.scanners[flaw_object.plugin]['plugin'].payloads(flaw)
        else:
            for scanner in self.scanners:
                if scanner in plugins:
                    if hasattr(self.scanners[scanner]['plugin'], 'payloads'):
                        payloads += self.scanners[scanner]['plugin'].payloads(flaw)

        return payloads

    def run_attack(self, project_uuid: str, flaw: str, options: dict) -> str:
        """ Run attack using scanner which has the feature to attack.

        :param str project_uuid: project UUID
        :param str flaw: flaw name
        :param dict options: options to set in scanner
        :return str: attack log
        """

        flaws = FlawDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        if flaws.filter(name=flaw).exists():
            flaw_object = flaws.get(name=flaw)

            if flaw_object.exploitable:
                if flaw_object.plugin in plugins:
                    if hasattr(self.scanners[flaw_object.plugin]['plugin'], 'attack'):
                        return self.scanners[flaw_object.plugin]['plugin'].attack(flaw, options)
        else:
            for scanner in self.scanners:
                if scanner in plugins:
                    if hasattr(self.scanners[scanner]['plugin'], 'attack'):
                        return self.scanners[scanner]['plugin'].attack(flaw, options)

        return '[!] Unfortunately this flaw is not exploitable.'

    def session_upload(self, project_uuid: str, session: int, local_file: str, remote_path: str) -> None:
        """ Upload file to session.

        :param str project_uuid: project UUID
        :param int session: session to upload file to
        :param str local_file: file to upload to session
        :param str remote_path: path to save uploaded file
        :return None: None
        """

        if project_uuid not in self.upload_queue:
            self.upload_queue[project_uuid] = {}

        if session not in self.upload_queue[project_uuid]:
            self.upload_queue[project_uuid][session] = {}

        self.upload_queue[project_uuid][session].update({
            str(uuid.uuid4()): [local_file, remote_path]
        })

        self.run_upload_queue(project_uuid)

    def session_download(self, project_uuid: str, session: int, remote_file: str, local_path: str) -> None:
        """ Download file from session.

        :param str project_uuid: project UUID
        :param int session: session to download file from
        :param str remote_file: file to download from session
        :param str local_path: path to save downloaded file
        :return None: None
        """

        if project_uuid not in self.download_queue:
            self.download_queue[project_uuid] = {}

        if session not in self.download_queue[project_uuid]:
            self.download_queue[project_uuid][session] = {}

        self.download_queue[project_uuid][session].update({
            str(uuid.uuid4()): [remote_file, local_path]
        })

        self.run_download_queue(project_uuid)

    def run_upload_queue(self, project_uuid: str) -> None:
        """ Run upload queue.

        :param str project_uuid: project UUID
        :return None: None
        """

        if project_uuid in self.upload_queue:
            if project_uuid not in self.upload_threads:
                self.upload_threads[project_uuid] = {}

            for session in self.upload_queue[project_uuid]:
                if session not in self.upload_threads[project_uuid]:
                    self.upload_threads[project_uuid][session] = threading.Thread()

                if not self.upload_threads[project_uuid][session].is_alive():
                    self.upload_threads[project_uuid][session] = threading.Thread(
                        target=self.run_session_upload_queue,
                        args=[project_uuid, session]
                    )
                    self.upload_threads[project_uuid][session].setDaemon(True)
                    self.upload_threads[project_uuid][session].start()

    def run_download_queue(self, project_uuid: str) -> None:
        """ Run download queue.

        :param str project_uuid: project UUID
        :return None: None
        """

        if project_uuid in self.download_queue:
            if project_uuid not in self.download_threads:
                self.download_threads[project_uuid] = {}

            for session in self.download_queue[project_uuid]:
                if session not in self.download_threads[project_uuid]:
                    self.download_threads[project_uuid][session] = threading.Thread()

                if not self.download_threads[project_uuid][session].is_alive():
                    self.download_threads[project_uuid][session] = threading.Thread(
                        target=self.run_session_download_queue,
                        args=[project_uuid, session]
                    )
                    self.download_threads[project_uuid][session].setDaemon(True)
                    self.download_threads[project_uuid][session].start()

    def run_session_upload_queue(self, project_uuid: str, session: int) -> None:
        """ Run session upload queue.

        :param str project_uuid: project UUID
        :param int session: session to run upload queue for
        :return None: None
        """

        while True:
            sessions = SessionDB.objects.filter(project=project_uuid)
            plugins = self.projects.get_project(project_uuid).plugins

            session_object = sessions.get(session=session)
            jobs = self.upload_queue[project_uuid][session]

            if session_object.plugin in plugins:
                if hasattr(self.scanners[session_object.plugin]['plugin'], 'upload'):
                    for job in list(jobs):
                        try:
                            self.scanners[session_object.plugin]['plugin'].upload(
                                jobs[job][0], jobs[job][1]
                            )
                        except Exception:
                            pass

                        jobs.pop(job)

            if not jobs:
                break

    def run_session_download_queue(self, project_uuid: str, session: int) -> None:
        """ Run session download queue.

        :param str project_uuid: project UUID
        :param int session: session to run download queue for
        :return None: None
        """

        while True:
            sessions = SessionDB.objects.filter(project=project_uuid)
            plugins = self.projects.get_project(project_uuid).plugins

            session_object = sessions.get(session=session)
            jobs = self.download_queue[project_uuid][session]

            if session_object.plugin in plugins:
                if hasattr(self.scanners[session_object.plugin]['plugin'], 'download'):
                    for job in list(jobs):
                        try:
                            self.scanners[session_object.plugin]['plugin'].download(
                                jobs[job][0], jobs[job][1]
                            )
                        except Exception:
                            pass

                        jobs.pop(job)

            if not jobs:
                break

    def check_session_busy(self, project_uuid: str, session: int) -> bool:
        """ Check if session is busy.

        :param str project_uuid: project UUID
        :param int session: session to check
        :return bool: True if busy else False
        """

        if project_uuid in self.download_queue:
            if session in self.download_queue[project_uuid]:
                return True

        if project_uuid in self.upload_queue:
            if session in self.upload_queue[project_uuid]:
                return True

        return False

    def session_execute(self, project_uuid: str, session: int, command: str) -> str:
        """ Execute command on session.

        :param str project_uuid: project UUID
        :param int session: session to execute command on
        :param str command: command to execute on session
        :return str: command output
        """

        sessions = SessionDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        session_object = sessions.get(session=session)

        if session_object.plugin in plugins:
            if hasattr(self.scanners[session_object.plugin]['plugin'], 'execute'):
                try:
                    return self.scanners[session_object.plugin]['plugin'].execute(
                        session, command
                    )
                except Exception:
                    pass
        return ''

    def get_flaw_options(self, project_uuid: str, flaw: str) -> dict:
        """ Get flaw options.

        :param str project_uuid: project UUID
        :param str flaw: flaw name
        :return dict: flaw options
        """

        flaws = FlawDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        if flaws.filter(name=flaw).exists():
            flaw_object = flaws.get(name=flaw)

            if flaw_object.plugin in plugins:
                if hasattr(self.scanners[flaw_object.plugin]['plugin'], 'options'):
                    return self.scanners[flaw_object.plugin]['plugin'].options(flaw)
        else:
            for scanner in self.scanners:
                if scanner in plugins:
                    if hasattr(self.scanners[scanner]['plugin'], 'options'):
                        return self.scanners[scanner]['plugin'].options(flaw)

        return {}

    def close_session(self, project_uuid: str, session: int) -> None:
        """ Close session.

        :param str project_uuid: project UUID
        :param int session: session to close
        :return None: None
        """

        sessions = SessionDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        session_object = sessions.get(session=session)

        if session_object.plugin in plugins:
            if hasattr(self.scanners[session_object.plugin]['plugin'], 'close_session'):
                try:
                    self.scanners[session_object.plugin]['plugin'].close(session)
                except Exception:
                    pass

    def run_scan(self, project_uuid: str, scanners: list, gateway: str = '', cycle: bool = True) -> None:
        """ Run network scanner (thread mode).

        :param str project_uuid: project UUID
        :param str scanners: list of scanners to execute
        :param str gateway: custom gateway
        :param bool cycle: cyclic scanning through selected scanners
        :return None: None
        """

        self.job[project_uuid] = threading.Thread(target=self.start_scan, args=[
            project_uuid,
            scanners,
            gateway,
            cycle
        ])
        self.job[project_uuid].setDaemon(True)
        self.job[project_uuid].start()

    def get_flaw_details(self, project_uuid: str, flaw: str) -> dict:
        """ Get flaw details.

        :param str project_uuid: project UUID
        :param str flaw: host to get details for
        :return dict: flaw details
        """

        flaws = FlawDB.objects.filter(project=project_uuid)
        plugins = self.projects.get_project(project_uuid).plugins

        flaw_object = flaws.get(name=flaw)

        if flaw_object.plugin in plugins:
            if hasattr(self.scanners[flaw_object.plugin]['plugin'], 'attack'):
                return self.scanners[flaw_object.plugin]['plugin'].flaw(flaw)

        return {
            'name': flaw,
            'description': '',
            'platform': 'unix',
            'rank': ''
        }

    def get_host_details(self, project_uuid: str, host: str) -> dict:
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
            'colors': self.colors,
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

    def get_flaws(self, project_uuid: str) -> list:
        """ Get flaws available for project.

        :param str project_uuid: project UUID
        :return list: list of flaws available for project
        """

        flaws = []
        plugins = self.projects.get_project(project_uuid).plugins

        for scanner in self.scanners:
            if scanner in plugins:
                if hasattr(self.scanners[scanner]['plugin'], 'flaws'):
                    flaws += self.scanners[scanner]['plugin'].flaws()

        return flaws

    def get_sessions(self, project_uuid: str) -> QuerySet:
        """ Get sessions available for project.

        NOTE: Sessions are objects that contain an image of TCP connection
        with target that has been attacked. Sessions can be closed, manipulated,
        you can send commands to it, download/upload files.

        :param str project_uuid: project UUID
        :return QuerySet: sessions available for project
        """

        plugins = self.projects.get_project(project_uuid).plugins

        for scanner in self.scanners:
            if scanner in plugins:
                if hasattr(self.scanners[scanner]['plugin'], 'sessions'):
                    self.scanners[scanner]['plugin'].sessions(project_uuid)

        return SessionDB.objects.filter(project=project_uuid)

    def get_scanners(self, project_uuid: str) -> dict:
        """ Get all scanners available for project.

        :param str project_uuid: project UUID
        :return dict: all scanners available for project
        """

        scanners = {}
        plugins = self.projects.get_project(project_uuid).plugins

        for scanner in self.scanners:
            if scanner in plugins:
                scanners[scanner] = self.scanners[scanner]

        return scanners

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

        session_platforms = {}
        session_countries = {}
        session_types = {}

        for session in sessions:
            if session.platform not in session_platforms:
                session_platforms[session.platform] = 0
            session_platforms[session.platform] += 1

            if session.country not in session_countries:
                session_countries[session.country] = 0
            session_countries[session.country] += 1

            if session.type not in session_types:
                session_types[session.type] = 0
            session_types[session.type] += 1

        data = {
            'animate': True,
            'scanners': self.get_scanners(project_uuid).items(),
            'colors': self.colors,

            'networks': networks,
            'hosts': hosts,
            'flaws': flaws,

            'sessions': sessions,
            'download_queue': {}.items(),
            'upload_queue': {}.items(),

            'services': [list(services.keys()), list(services.values())],
            'platforms': [list(platforms.keys()), list(platforms.values())],
            'flaws_ranks': [list(flaws_ranks.keys()), list(flaws_ranks.values())],

            'session_platforms': [list(session_platforms.keys()), list(session_platforms.values())],
            'session_countries': [list(session_countries.keys()), list(session_countries.values())],
            'session_types': [list(session_types.keys()), list(session_types.values())]
        }

        if project_uuid in self.download_queue:
            data.update({
                'download_queue': self.download_queue[project_uuid].items()
            })

        if project_uuid in self.upload_queue:
            data.update({
                'upload_queue': self.upload_queue[project_uuid].items()
            })

        return data
