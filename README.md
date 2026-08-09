# Turris Sentinel Dynamic Firewall client

This client receives Sentinel Dynamic Firewall (Sentinel:DynFW) updates over
ZMQ and updates nftables accordingly.


## Requirements

See `requirements.txt` for needed Python3 packages.


## Get started

Check whether your Linux distributions nftables, on debian based systems it is the default.\
No need to configure tables, sets, chains, or rules manually - all are handled by the program.\
It is intended that a dedicated nftables table is used as it is wiped on start and exit but YMMV.

To install a systemd service, run
```sh
systemctl link etc/sentinel-fw.service
```

Edit both the variables file and service files to your liking.
```sh
nano etc/variables
systemctl edit --full sentinel-fw.service
systemctl daemon-reload
```

Python virtual environment is recommended, to create it, run
```sh
./init-env.sh
```

To start the service, enable it and start.
```sh
systemctl enable sentinel-fw.service
systemctl start sentinel-fw.service
systemctl status sentinel-fw.service
```

To read logs.
```sh
journalctl -u sentinel-fw.service
```

Check
```sh
env/bin/python main.py --help
```
for available configuration options.
