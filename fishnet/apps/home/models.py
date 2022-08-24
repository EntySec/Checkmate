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

from django.db import models
from picklefield.fields import PickledObjectField


class Session(models.Model):
    session = models.PositiveIntegerField()
    platform = models.CharField(max_length=250)
    architecture = models.CharField(max_length=250)
    type = models.CharField(max_length=250)
    host = models.CharField(max_length=250)
    port = models.PositiveIntegerField()
    latitude = models.CharField(max_length=250)
    longitude = models.CharField(max_length=250)
    country = models.CharField(max_length=250)
    project = models.CharField(max_length=250)
    plugin = models.CharField(max_length=250)

    def __str__(self):
        return self.session


class Network(models.Model):
    gateway = models.CharField(max_length=250)
    iface = models.CharField(max_length=250)
    method = models.CharField(max_length=250)
    project = models.CharField(max_length=250)

    def __str__(self):
        return self.gateway


class Team(models.Model):
    name = models.CharField(max_length=250)
    purpose = models.CharField(max_length=250)
    leader = models.CharField(max_length=250)
    users = PickledObjectField()

    def __str__(self):
        return self.name


class Setting(models.Model):
    user = models.CharField(max_length=250)
    dark = models.BooleanField()

    def __str__(self):
        return self.user


class Host(models.Model):
    host = models.CharField(max_length=250)
    mac = models.CharField(max_length=250)
    vendor = models.CharField(max_length=250)
    dns = models.CharField(max_length=250)
    ports = PickledObjectField()
    gateway = models.CharField(max_length=250)
    platform = models.CharField(max_length=250)
    project = models.CharField(max_length=250)

    def __str__(self):
        return self.host


class Flaw(models.Model):
    name = models.CharField(max_length=250)
    family = models.CharField(max_length=250)
    host = models.CharField(max_length=250)
    port = models.PositiveIntegerField()
    service = models.CharField(max_length=250)
    rank = models.CharField(max_length=250)
    project = models.CharField(max_length=250)
    plugin = models.CharField(max_length=250)
    exploitable = models.BooleanField()

    def __str__(self):
        return self.name


class Project(models.Model):
    uuid = models.CharField(max_length=250)
    name = models.CharField(max_length=250)
    category = models.CharField(max_length=250)
    author = models.CharField(max_length=250)
    team = models.CharField(max_length=250)
    plugins = PickledObjectField()
    archived = models.BooleanField()
    running = models.BooleanField()

    def __str__(self):
        return self.uuid
