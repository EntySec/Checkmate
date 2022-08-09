"""
This plugin requires Fishnet: https://fishnet.com
Current source: https://github.com/EntySec/Fishnet
"""

import re
import sys
import socket
import requests
import ipaddress

from io import StringIO

from fishnet.lib.plugin import Plugin
from fishnet.lib.projects import Projects
from fishnet.lib.storage import Storage

from hatsploit.lib.runtime import Runtime
from hatsploit.lib.modules import Modules
from hatsploit.lib.sessions import Sessions


class FishnetPlugin(Plugin, Projects, Storage, Sessions):
    runtime = Runtime()

    runtime.check()
    runtime.start(build_base=True)

    modules = Modules()

    details = {
        'Name': 'HatSploit',
        'Category': 'network'
    }

    def sessions(self, project_uuid):
        sessions = self.get_sessions()
        sessions_db = self.sessions_db()

        if sessions:
            for session_id in sessions:
                if not sessions_db.filter(project=project_uuid).filter(
                        plugin=self.details['Name']
                ).filter(session=session_id).exists():
                    host = sessions[session_id]['Host']

                    if ipaddress.ip_address(host).is_private:
                        host = requests.get("https://myexternalip.com/json").json()['ip']

                    location = requests.get(f"http://ipinfo.io/{host}").json()

                    sessions_db.create(
                        project=project_uuid,
                        plugin=self.details['Name'],
                        session=session_id,
                        platform=sessions[session_id]['Platform'],
                        architecture=sessions[session_id]['Architecture'],
                        type=sessions[session_id]['Type'],
                        host=sessions[session_id]['Host'],
                        port=sessions[session_id]['Port'],
                        latitude=location['loc'].split(',')[0],
                        longitude=location['loc'].split(',')[1],
                        country=location['country']
                    )

        for session in sessions_db.all():
            if sessions:
                if session.session not in sessions:
                    sessions_db.filter(session=session.session).delete()
            else:
                sessions_db.filter(session=session.session).delete()

    def flaw(self, flaw):
        module = self.modules.search_module(flaw)
        object = self.modules.get_module_object(module)

        return {
            'name': object['Name'],
            'description': object['Description'],
            'platform': object['Platform'],
            'rank': object['Rank']
        }

    def options(self, flaw):
        module = self.modules.search_module(flaw)

        self.modules.use_module(module)
        self.runtime.update()

        return self.modules.get_current_module().options

    def attack(self, flaw, options):
        self.disable_auto_interaction()

        module = self.modules.search_module(flaw)

        self.modules.use_module(module)
        self.runtime.update()

        for option in options:
            if option in self.modules.get_current_module().options:
                self.modules.set_current_module_option(option, options[option])

        temp = sys.stdout
        result = StringIO()
        sys.stdout = result

        self.modules.run_current_module()
        sys.stdout = temp

        return re.compile(
            r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
        ).sub('', result.getvalue().replace("\n", "")).strip()

    def scan(self, host, project_uuid):
        modules = self.modules.get_modules()
        flaws_db = self.flaws_db()

        if modules:
            for module in modules['modules']:
                module = modules['modules'][module]

                self.modules.use_module(module['Module'])
                self.runtime.update()

                if 'HOST' in self.modules.get_current_module().options:
                    self.modules.set_current_module_option('HOST', host.host)

                    if 'PORT' in self.modules.get_current_module().options and host.ports:
                        for port in host.ports:
                            self.modules.set_current_module_option('PORT', str(port))
                            result = self.runtime.catch(self.modules.check_current_module)

                            if result and result is not Exception:
                                flaws_db.update_or_create(
                                    project=project_uuid,
                                    plugin=self.details['Name'],
                                    name=module['Name'],
                                    host=host.host,
                                    port=port,

                                    defaults={
                                        'rank': module['Rank'],
                                        'family': module['Platform'],
                                        'service': host.ports[port],
                                        'exploitable': True
                                    }
                                )
                    else:
                        result = self.runtime.catch(self.modules.check_current_module)

                        if 'PORT' in self.modules.get_current_module().options:
                            port = int(self.modules.get_current_module().options['PORT']['Value'])
                        else:
                            port = 0

                        try:
                            service = socket.getservbyport(port)
                        except Exception:
                            service = 'unidentified'

                        if result and result is not Exception:
                            flaws_db.update_or_create(
                                project=project_uuid,
                                plugin=self.details['Name'],
                                name=module['Name'],
                                host=host.host,
                                port=port,

                                defaults={
                                    'rank': module['Rank'],
                                    'family': module['Platform'],
                                    'service': service,
                                    'exploitable': True
                                }
                            )
    
    def run(self, args):
        project_uuid = args['project_uuid']
        hosts_db = self.hosts_db()

        while True:
            if not self.check_project_running(project_uuid):
                break

            hosts = hosts_db.filter(project=project_uuid)

            for host in hosts:
                self.scan(host, project_uuid)
