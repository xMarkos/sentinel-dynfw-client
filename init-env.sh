#!/bin/bash

python -m venv env --clear --system-site-packages --without-pip
env/bin/python -m pip install -r requirements.txt

[[ -e etc/variables ]] || cp etc/variables.default etc/variables
[[ -e etc/sentinel-fw.service ]] || cp etc/sentinel-fw.service.default etc/sentinel-fw.service
