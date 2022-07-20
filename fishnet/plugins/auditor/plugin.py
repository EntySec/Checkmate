"""
This plugin requires Fishnet: https://fishnet.com
Current source: https://github.com/EntySec/Fishnet
"""

import threading

from pex.net import Net

from fishnet.lib.plugin import Plugin
from fishnet.lib.projects import Projects
from fishnet.lib.storage import Storage


class FishnetPlugin(Plugin, Projects, Storage):
    net = Net()

    scan_job = threading.Thread()

    details = {
        'Name': 'Auditor',
        'Category': 'network'
    }

    def run(self, args):
        gateway = args['gateway']
        iface = args['iface']
        method = args['method']
        project_uuid = args['project_uuid']

        hosts_db = self.hosts_db()
        networks_db = self.networks_db()

        while True:
            if not self.check_project_running(project_uuid):
                break

            if not self.scan_job.is_alive():
                self.scan_job = threading.Thread(
                    target=self.net.start_full_scan,
                    args=[
                        gateway,
                        iface,
                        method
                    ]
                )

                self.scan_job.setDaemon(True)
                self.scan_job.start()

            result = self.net.full_scan_result()

            if result:
                for gateway in result:
                    for iface in result[gateway]:
                        networks_db.update_or_create(
                            project=project_uuid,
                            gateway=gateway,
                            defaults={
                                'iface': iface,
                                'method': method
                            }
                        )

                        for host in result[gateway][iface]:
                            hosts_db.update_or_create(
                                project=project_uuid,
                                host=host,
                                defaults={
                                    'mac': result[gateway][iface][host]['mac'],
                                    'vendor': result[gateway][iface][host]['vendor'],
                                    'dns': result[gateway][iface][host]['dns'],
                                    'platform': result[gateway][iface][host]['platform'],
                                    'ports': result[gateway][iface][host]['ports'],
                                    'gateway': gateway
                                }
                            )
