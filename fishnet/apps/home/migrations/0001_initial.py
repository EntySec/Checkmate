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

from django.db import migrations, models
from picklefield.fields import PickledObjectField


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Session',
            fields=[
                ('session', models.PositiveIntegerField()),
                ('platform', models.CharField(max_length=250)),
                ('architecture', models.CharField(max_length=250)),
                ('type', models.CharField(max_length=250)),
                ('host', models.CharField(max_length=250)),
                ('port', models.PositiveIntegerField()),
                ('latitude', models.CharField(max_length=250)),
                ('longitude', models.CharField(max_length=250)),
                ('project', models.CharField(max_length=250)),
                ('plugin', models.CharField(max_length=250))
            ]
        ),
        migrations.CreateModel(
            name='Network',
            fields=[
                ('project', models.CharField(max_length=250)),
                ('gateway', models.CharField(max_length=250)),
                ('iface', models.CharField(max_length=250)),
                ('method', models.CharField(max_length=250))
            ]
        ),
        migrations.CreateModel(
            name="Setting",
            fields=[
                ('user', models.CharField(max_length=250)),
                ('dark', models.BooleanField())
            ]
        ),
        migrations.CreateModel(
            name="Team",
            fields=[
                ('name', models.CharField(max_length=250)),
                ('purpose', models.CharField(max_length=250)),
                ('leader', models.CharField(max_length=250)),
                ('users', PickledObjectField())
            ]
        ),
        migrations.CreateModel(
            name="Host",
            fields=[
                ('host', models.CharField(max_length=250)),
                ('mac', models.CharField(max_length=250)),
                ('vendor', models.CharField(max_length=250)),
                ('dns', models.CharField(max_length=250)),
                ('platform', models.CharField(max_length=250)),
                ('project', models.CharField(max_length=250)),
                ('gateway', models.CharField(max_length=250)),
                ('ports', PickledObjectField())
            ]
        ),
        migrations.CreateModel(
            name="Flaw",
            fields=[
                ('name', models.CharField(max_length=250)),
                ('host', models.CharField(max_length=250)),
                ('port', models.PositiveIntegerField()),
                ('service', models.CharField(max_length=250)),
                ('family', models.CharField(max_length=250)),
                ('rank', models.CharField(max_length=250)),
                ('project', models.CharField(max_length=250)),
                ('plugin', models.CharField(max_length=250))
            ]
        ),
        migrations.CreateModel(
            name="Project",
            fields=[
                ('uuid', models.CharField(max_length=250)),
                ('name', models.CharField(max_length=250)),
                ('category', models.CharField(max_length=250)),
                ('author', models.CharField(max_length=250)),
                ('team', models.CharField(max_length=250)),
                ('running', models.BooleanField()),
                ('archived', models.BooleanField())
            ]
        )
    ]
