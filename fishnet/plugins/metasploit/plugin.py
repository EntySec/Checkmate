"""
This plugin requires Fishnet: https://fishnet.com
Current source: https://github.com/EntySec/Fishnet
"""

import os

from fishnet.lib.plugin import Plugin
from fishnet.lib.projects import Projects
from fishnet.lib.storage import Storage

from pex.string import String

from pymetasploit3.msfrpc import MsfRpcClient


class FishnetPlugin(Plugin, Projects, Storage):
    msf_password = String().random_string(8)

    os.system(f'msfrpcd -p {msf_password} -S')
    msf = MsfRpcClient(msf_password)

    details = {
        'Name': 'Metasploit',
        'Category': 'network'
    }

    def sessions(self, project_uuid):
        sessions = self.msf.sessions.list
        sessions_db = self.sessions_db()

        if sessions:
            for session_id in sessions:
                if not sessions_db.filter(project=project_uuid).filter(
                        plugin=self.details['Name']
                ).filter(session=session_id).exists():
                    host = sessions[session_id]['session_host']

                    if ipaddress.ip_address(host).is_private:
                        host = requests.get("https://myexternalip.com/json").json()['ip']

                    location = requests.get(f"http://ipinfo.io/{host}").json()

                    sessions_db.create(
                        project=project_uuid,
                        plugin=self.details['Name'],
                        session=session_id,
                        platform='unix',
                        architecture='generic',
                        type=sessions[session_id]['type'],
                        host=host,
                        port=sessions[session_id]['session_port'],
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

    def execute(self, session_id, command):
        return self.msf.sessions.session(session_id).run_with_output(command)

    def close(self, session_id):
        pass

    def payloads(self, flaw):
        return self.msf.modules.use('exploit', flaw).targetpayloads()

    def flaws(self):
        return self.msf.modules.exploits

    def flaw(self, flaw):
        return {
            'name': object['Name'],
            'description': None
        }

    def run(self, args):
        project_uuid = args['project_uuid']
        hosts_db = self.hosts_db()

        while True:
            if not self.check_project_running(project_uuid):
                break

            hosts = hosts_db.filter(project=project_uuid)

            for host in hosts:
                self.scan(host, project_uuid)
