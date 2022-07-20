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
import importlib


class Plugins:
    plugins_paths = [
        f'{os.path.dirname(os.path.dirname(__file__))}/plugins/',
        os.path.expanduser('~/.fishnet/plugins/')
    ]

    def load_plugins(self, category):
        plugins = {}

        for plugins_path in self.plugins_paths:
            plugins_path = os.path.split(plugins_path)[0]

            if not os.path.isdir(plugins_path):
                continue

            for dest, _, files in os.walk(plugins_path):
                for file in files:
                    if file.endswith('py'):
                        plugin = dest + '/' + file

                        try:
                            spec = importlib.util.spec_from_file_location(plugin, plugin)
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)

                            plugin_object = module.FishnetPlugin()

                            if plugin_object.details['Category'] == category:
                                plugin_name = plugin_object.details['Name']
                                if plugin_name not in plugins:
                                    plugins[plugin_name] = {}

                                plugins[plugin_name]['plugin'] = plugin_object
                                plugins[plugin_name]['logo'] = os.path.split(dest)[1] + '/plugin.png'

                        except Exception as e:
                            print(f"Failed to load {file[:-3]} plugin, error: ({str(e)})!")

        return plugins
