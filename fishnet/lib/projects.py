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

import uuid

from fishnet.apps.home.models import Project, Host, Network, Session, Flaw
from fishnet.lib.teams import Teams


class Projects:
    teams = Teams()

    @staticmethod
    def get_projects():
        return Project.objects.all()

    @staticmethod
    def get_project(project_uuid):
        return Project.objects.get(uuid=project_uuid)

    @staticmethod
    def check_project(project_uuid):
        return Project.objects.filter(uuid=project_uuid).exists()

    def check_project_running(self, project_uuid):
        if self.check_project(project_uuid):
            return Project.objects.get(uuid=project_uuid).running
        return False

    def check_project_perms(self, project_uuid, username):
        if self.check_project(project_uuid):
            project = self.get_project(project_uuid)
            if project.team:
                if username in self.teams.get_team(
                    project.team
                ).users:
                    return True
            else:
                if username == project.author:
                    return True
        return False

    @staticmethod
    def change_projects_author(username, new_username):
        if Project.objects.filter(author=username).exists():
            Project.objects.filter(author=username).update(author=new_username)

    @staticmethod
    def change_projects_team(team, new_team):
        if Project.objects.filter(team=team).exists():
            Project.objects.filter(team=team).update(team=new_team)

    @staticmethod
    def check_project_author(project_uuid, username):
        if Project.objects.filter(uuid=project_uuid).exists():
            if Project.objects.get(uuid=project_uuid).author == username:
                return True
        return False

    @staticmethod
    def update_name(project_uuid, new_name):
        if Project.objects.filter(uuid=project_uuid).exists():
            Project.objects.filter(uuid=project_uuid).update(name=new_name)

    @staticmethod
    def create_project(name, category, author, team, plugins):
        project_uuid = str(uuid.uuid4())

        Project.objects.create(
            uuid=project_uuid,
            name=name,
            category=category,
            author=author,
            team=team,
            plugins=plugins,
            archived=False,
            running=False
        )

        return project_uuid

    def stop_project(self, project_uuid):
        if self.check_project(project_uuid):
            Project.objects.filter(uuid=project_uuid).update(running=False)

    def run_project(self, project_uuid):
        if self.check_project(project_uuid):
            Project.objects.filter(uuid=project_uuid).update(running=True)

    def archive_project(self, project_uuid):
        if self.check_project(project_uuid):
            Project.objects.filter(uuid=project_uuid).update(archived=True)

    def activate_project(self, project_uuid):
        if self.check_project(project_uuid):
            Project.objects.filter(uuid=project_uuid).update(archived=False)

    def delete_project(self, project_uuid):
        if self.check_project(project_uuid):
            Host.objects.filter(project=project_uuid).delete()
            Flaw.objects.filter(project=project_uuid).delete()
            Session.objects.filter(project=project_uuid).delete()
            Network.objects.filter(project=project_uuid).delete()
            Project.objects.filter(uuid=project_uuid).delete()