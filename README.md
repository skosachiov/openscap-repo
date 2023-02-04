# openscap-repo

A small python script allows you to scan the deb package repository for vulnerabilities published by the Debian project. I could not find a similar functionality in the openscap scanner.

## install dependencies

apt install python3-apt
wget -O debian-cve-all.json https://security-tracker.debian.org/tracker/data/json
chmod a+x openscap-repo.py

## run

./openscap-repo.py buster debian-cve-all.json /var/cache/apt-mirror

## links

wget https://cve.mitre.org/data/downloads/allitems.xml.gz
https://nvd.nist.gov/developers/vulnerabilities