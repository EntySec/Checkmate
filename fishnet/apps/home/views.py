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

from django import template
from django.contrib.auth import get_user_model, login, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.template import loader, Context, Template
from django.urls import reverse

from fishnet.lib.network import Network
from fishnet.lib.projects import Projects
from fishnet.lib.settings import Settings
from fishnet.lib.teams import Teams

network = Network()
projects = Projects()
settings = Settings()
teams = Teams()


def realtime_update(request):
    context = {}

    if request.method == 'POST':
        if 'update' in request.POST:
            load_template = request.path.split('/')
            endpoint = load_template[-1]
            update = request.POST['update']

            if request.POST['project_uuid']:
                project_uuid = request.POST['project_uuid']
                project = projects.get_project(project_uuid)
                if projects.get_project(project_uuid).category == 'network':
                    context = network.get_scan(project_uuid)

                    if endpoint == 'attack':
                        context.update({
                            'all_flaws': network.get_flaws(),
                        })

                        if 'flaw_options' in request.POST:
                            flaw = request.POST['flaw_options']
                            context.update({
                                'current_flaw': flaw,
                                'options': network.get_flaw_options(project_uuid, flaw).items(),
                                'all_payloads': network.get_payloads(project_uuid, flaw)
                            })

                context.update({
                    'segment': endpoint,
                    'project': project,
                    'dark_mode': settings.get_settings(request.user.username).dark,
                    'animate': request.POST['animate'] if 'animate' in request.POST else False
                })

                html_template = loader.get_template(f'updates/{update}.html')
                return HttpResponse(html_template.render(context, request))

            context.update({
                'segment': endpoint,
                'dark_mode': settings.get_settings(request.user.username).dark,
                'teams': teams.get_teams(),
                'users': get_user_model().objects.all(),
                'projects': projects.get_projects()
            })

            html_template = loader.get_template(f'updates/{update}.html')
            return HttpResponse(html_template.render(context, request))


def clean_post_data(request):
    if request.method == 'POST':
        return HttpResponseRedirect(request.path)


def allow_edit_profile(request):
    if request.method == 'POST':
        user = get_user_model()

        if 'edit_profile' in request.POST and 'password' in request.POST:
            password = request.POST['password']

            if user.objects.get(username=request.user.username).check_password(password):
                if 'email' in request.POST:
                    email = request.POST['email']
                    user.objects.filter(username=request.user.username).update(email=email)

                if 'first_name' in request.POST:
                    first_name = request.POST['first_name']
                    user.objects.filter(username=request.user.username).update(first_name=first_name)

                if 'last_name' in request.POST:
                    last_name = request.POST['last_name']
                    user.objects.filter(username=request.user.username).update(last_name=last_name)

                if 'new_password' in request.POST:
                    new_password = request.POST['new_password']
                    username = request.user.username

                    u = user.objects.get(username=request.user.username)
                    u.set_password(new_password)
                    u.save()

                    user = authenticate(username=username, password=password)
                    login(request, user)

                if 'username' in request.POST:
                    username = request.POST['username']

                    if not user.objects.filter(username=username).exists():
                        user.objects.filter(username=request.user.username).update(username=username)

                        settings.change_setting_user(request.user.username, username)
                        teams.change_team_leader(request.user.username, username)
                        teams.change_team_user(request.user.username, username)
                        projects.change_projects_author(request.user.username, username)

                        request.user.username = username


def allow_toggle_dark(request):
    settings.create_setting(request.user.username, {'dark': False})

    if request.method == 'POST':
        if 'toggle_dark' in request.POST:
            settings.update_setting(request.user.username, {
                'dark': bool(int(request.POST['toggle_dark']))
            })


def allow_manage_teams(request):
    if request.method == 'POST':
        if 'delete_team' in request.POST:
            name = request.POST['delete_team']
            if teams.check_team_leader(name, request.user.username):
                teams.delete_team(name)

        if 'edit_team' in request.POST:
            name = request.POST['edit_team']
            if teams.check_team_leader(name, request.user.username):
                if 'name' in request.POST:
                    teams.update_name(name, request.POST['name'])
                    projects.change_projects_team(name, request.POST['name'])


def allow_create_team(request):
    if request.method == 'POST':
        if 'create_team' in request.POST:
            name = request.POST['create_team']
            purpose = request.POST['purpose']

            users = []
            if 'users' in request.POST:
                users = request.POST.getlist('users')

            users.append(request.user.username)

            leader = request.user.username
            teams.create_team(name, purpose, users, leader)


@login_required(login_url='/login/')
def index_page(request):
    context = {'segment': 'index'}

    allow_toggle_dark(request)
    allow_manage_teams(request)
    allow_create_team(request)
    allow_edit_profile(request)

    update = realtime_update(request)
    if update:
        return update

    context.update({
        'dark_mode': settings.get_settings(request.user.username).dark,
        'projects': projects.get_projects(),
        'teams': teams.get_teams(),
        'users': get_user_model().objects.all()
    })

    post_redirect = clean_post_data(request)
    if clean_post_data(request):
        return post_redirect

    html_template = loader.get_template('home/index.html')
    return HttpResponse(html_template.render(context, request))


@login_required(login_url="/login/")
def projects_page(request):
    context = {'segment': 'projects'}

    allow_toggle_dark(request)
    allow_manage_teams(request)
    allow_create_team(request)
    allow_edit_profile(request)

    if request.method == 'POST':
        if 'archive_project' in request.POST:
            project_uuid = request.POST['archive_project']
            if projects.check_project_author(project_uuid, request.user.username):
                projects.stop_project(project_uuid)
                projects.archive_project(project_uuid)

        if 'delete_project' in request.POST:
            project_uuid = request.POST['delete_project']
            if projects.check_project_author(project_uuid, request.user.username):
                projects.delete_project(project_uuid)

        if 'activate_project' in request.POST:
            project_uuid = request.POST['activate_project']
            if projects.check_project_author(project_uuid, request.user.username):
                projects.activate_project(project_uuid)

        if 'edit_project' in request.POST:
            project_uuid = request.POST['edit_project']
            if projects.check_project_author(project_uuid, request.user.username):
                if 'name' in request.POST:
                    projects.update_name(project_uuid, request.POST['name'])

        if 'create_project' in request.POST:
            name = request.POST['name']
            category = request.POST['category']
            team = request.POST['team']

            if team == 'private':
                team = ''

            author = request.user.username
            projects.create_project(name, category, author, team)

    context.update({
        'dark_mode': settings.get_settings(request.user.username).dark,
        'projects': projects.get_projects(),
        'teams': teams.get_teams(),
        'users': get_user_model().objects.all()
    })

    post_redirect = clean_post_data(request)
    if clean_post_data(request):
        return post_redirect

    html_template = loader.get_template('home/projects.html')
    return HttpResponse(html_template.render(context, request))


@login_required(login_url="/login/")
def pages(request):
    context = {}

    allow_toggle_dark(request)
    allow_manage_teams(request)
    allow_create_team(request)
    allow_edit_profile(request)

    context['dark_mode'] = settings.get_settings(request.user.username).dark

    update = realtime_update(request)
    if update:
        return update

    try:
        load_template = request.path.split('/')
        endpoint = load_template[-1]

        if len(load_template) >= 3:
            project_uuid = load_template[-2]

            if project_uuid:
                if projects.check_project_perms(project_uuid, request.user.username) and \
                        not projects.get_project(project_uuid).archived:
                    if request.method == 'POST':
                        if 'project_run' in request.POST:
                            projects.run_project(project_uuid)
                            if projects.get_project(project_uuid).category == 'network':
                                if 'gateway' in request.POST:
                                    network.run_scan(
                                        project_uuid,
                                        request.POST.getlist('scanners'),
                                        request.POST['gateway']
                                    )
                                else:
                                    network.run_scan(
                                        project_uuid,
                                        request.POST.getlist('scanners')
                                    )

                        elif 'project_stop' in request.POST:
                            projects.stop_project(project_uuid)
                            if projects.get_project(project_uuid).category == 'network':
                                network.stop_scan(project_uuid)

                        elif 'project_archive' in request.POST:
                            if projects.check_project_author(project_uuid, request.user.username):
                                projects.stop_project(project_uuid)
                                if projects.get_project(project_uuid).category == 'network':
                                    network.stop_scan(project_uuid)

                                projects.archive_project(project_uuid)
                                return redirect("/projects")

                    if projects.get_project(project_uuid).category == 'network':
                        if request.method == 'POST':
                            if 'host_details' in request.POST:
                                host = request.POST['host_details']
                                context = network.get_host_details(project_uuid, host)

                                html_template = loader.get_template('updates/host_details.html')
                                return HttpResponse(html_template.render(context, request))

                            if 'flaw_details' in request.POST:
                                flaw = request.POST['flaw_details']
                                context = network.get_flaw_details(project_uuid, flaw)

                                html_template = loader.get_template('updates/flaw_details.html')
                                return HttpResponse(html_template.render(context, request))

                            if 'attack_details' in request.POST:
                                flaw = request.POST['attack_details']
                                context = {
                                    'options': network.get_flaw_options(project_uuid, flaw),
                                    'flaw': flaw
                                }

                                for option in context['options']:
                                    if option.lower() == 'host':
                                        context['options'][option] = request.POST['host']
                                    elif option.lower() == 'port':
                                        context['options'][option] = request.POST['port']

                                context['options'] = context['options'].items()

                                html_template = loader.get_template('updates/attack_details.html')
                                return HttpResponse(html_template.render(context, request))

                            if 'session' in request.POST:
                                if 'command' in request.POST:
                                    result = network.session_execute(
                                        project_uuid,
                                        request.POST['session'],
                                        request.POST['command']
                                    )

                                    file = Template('<pre>{{ result }}</pre>')
                                    return HttpResponse(file.render(
                                        Context({
                                            'result': result
                                        })
                                    ))

                            if 'close_session' in request.POST:
                                network.close_session(project_uuid, request.POST['close_session'])

                            if 'set_option' in request.POST:
                                flaw = request.POST['set_option']
                                option = request.POST['option']
                                value = request.POST['value']

                                network.set_option(project_uuid, flaw, option, value)
                                file = Template('')

                                return HttpResponse(file.render(
                                    Context({
                                    })
                                ))

                            if 'attack' in request.POST:
                                flaw = request.POST['attack']
                                options = network.get_flaw_options(project_uuid, flaw)

                                for option in list(options):
                                    if option in request.POST:
                                        options.update({
                                            option: request.POST[option]
                                        })

                                try:
                                    result = network.run_attack(project_uuid, flaw, options)

                                except RuntimeError as e:
                                    result = f"[-] {str(e)}"

                                except RuntimeWarning as w:
                                    result = f"[!] {str(w)}"

                                except Exception as e:
                                    result = f"[-] An error occured: {str(e)}!"

                                file = Template('<pre>{{ result }}</pre>')

                                return HttpResponse(file.render(
                                    Context({
                                        'result': result
                                    })
                                ))

                    project = projects.get_project(project_uuid)
                else:
                    raise template.TemplateDoesNotExist(endpoint)
            else:
                raise template.TemplateDoesNotExist(endpoint)
        else:
            if endpoint == 'admin':
                return HttpResponseRedirect(reverse('admin:index'))
            raise template.TemplateDoesNotExist(endpoint)

        context.update({
            'project': project,
            'segment': endpoint,
            'projects': projects.get_projects(),
            'teams': teams.get_teams()
        })

        post_redirect = clean_post_data(request)
        if clean_post_data(request):
            return post_redirect

        html_template = loader.get_template('home/' + endpoint + '.html')
        return HttpResponse(html_template.render(context, request))

    except template.TemplateDoesNotExist:
        html_template = loader.get_template('home/page-404.html')
        return HttpResponse(html_template.render(context, request))

    except Exception as e:
        context.update({
            'error': str(e),
        })

        html_template = loader.get_template('home/page-500.html')
        return HttpResponse(html_template.render(context, request))
