#!/usr/bin/env python
"""
    Python package for the fuzzware pipeline.
"""
import os
from setuptools import setup

def get_packages(rel_dir):
    packages = [rel_dir]
    for x in os.walk(rel_dir):
        # break into parts
        base = list(os.path.split(x[0]))
        if base[0] == "":
            del base[0]

        for mod_name in x[1]:
            packages.append(".".join(base + [mod_name]))

    return packages

setup(name='fuzzware_modeling',
    version='1.0',
    description='Python package for the fuzzware modeling component.',
    author='Tobias Scharnowski',
    author_email='tobias.scharnowski@rub.de',
    url='https://www.syssec.ruhr-uni-bochum.de/chair',
    packages=get_packages('fuzzware_modeling'),
    entry_points = {
        'console_scripts': [
            'fuzzware_model = fuzzware_modeling:main'
        ]
    }
)
