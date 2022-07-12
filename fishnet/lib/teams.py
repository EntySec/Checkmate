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

from fishnet.apps.home.models import Team


class Teams:
    @staticmethod
    def get_teams():
        return Team.objects.all()

    @staticmethod
    def get_team(name):
        if Team.objects.filter(name=name).exists():
            return Team.objects.get(name=name)

    @staticmethod
    def delete_team(name):
        if Team.objects.filter(name=name).exists():
            Team.objects.filter(name=name).delete()

    @staticmethod
    def change_team_leader(username, new_username):
        if Team.objects.filter(leader=username).exists():
            Team.objects.filter(leader=username).update(leader=new_username)

    @staticmethod
    def update_name(team_name, new_name):
        if Team.objects.filter(name=team_name).exists():
            Team.objects.filter(name=team_name).update(name=new_name)

    def change_team_user(self, username, new_username):
        for team in self.get_teams():
            if username in team.users:
                users = team.users
                users[users.index(username)] = new_username

                Team.objects.filter(name=team.name).update(users=users)

    @staticmethod
    def check_team_leader(team_name, username):
        if Team.objects.filter(name=team_name).exists():
            if Team.objects.get(name=team_name).leader == username:
                return True
        return False

    @staticmethod
    def create_team(name, purpose, users, leader):
        if not Team.objects.filter(name=name).exists():
            Team.objects.create(
                name=name,
                purpose=purpose,
                users=users,
                leader=leader
            )
