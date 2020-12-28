# Python OpenVuln Report

This project is heavily inspired by [@NWMichl](https://github.com/NWMichl)'s [openvuln](https://github.com/NWMichl/openvuln) Project.

This project re-implements some of the features found there in pure python, making use of nornir / netmiko / genie.

The reported os versions then get queried against Cisco's openVuln API to retrieve lists of known Security Issues of all os versions.

The information is then rendered into a markdown file like [THIS](openvuln.md).
