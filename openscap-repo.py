#!/usr/bin/python3
#
# ./openscap-repo.py <buster|bullseye|bookworm> <cve.json> </path/to/the/repo|https://path.to.the/Packages.gz>
# apt install python3-apt
# wget -O debian-cve-all.json https://security-tracker.debian.org/tracker/data/json

import sys, os, glob, json, re, apt_pkg, collections, gzip, urllib.request
apt_pkg.init_system()

def recursively_default_dict():
    return collections.defaultdict(recursively_default_dict)

def check_pkg_name(pkg_name, pkg_version, codename, cve_dict, out_dict):
    if pkg_name in cve_dict:
        for cve_key, cve_value in cve_dict[pkg_name].items():
            if codename in cve_value['releases'].keys():
                if "fixed_version" in cve_value['releases'][codename].keys():
                    fixed_version = cve_value['releases'][codename]['fixed_version']
                    status = cve_value['releases'][codename]['status']
                    if ":" in fixed_version: fixed_version = fixed_version.split(":")[1] # force colon remove
                    if apt_pkg.version_compare(pkg_version, fixed_version) < 0:
                        desc = cve_value['description'] if 'description' in cve_value.keys() else ""
                        out_dict[pkg_name][pkg_version][cve_key]['release'] = codename
                        out_dict[pkg_name][pkg_version][cve_key]['package'] = pkg_name
                        out_dict[pkg_name][pkg_version][cve_key]['fixed_version'] = fixed_version
                        out_dict[pkg_name][pkg_version][cve_key]['status'] = status
                        out_dict[pkg_name][pkg_version][cve_key]['description'] = desc

def main():
    out_dict = recursively_default_dict()
    codename = sys.argv[1]
    cve_file = sys.argv[2]
    repo_path = sys.argv[3]
    with open(cve_file) as f: cve_dict = json.load(f)
    if "://" in repo_path:
        response = urllib.request.urlopen(repo_path)
        content = gzip.decompress(response.read())
        decomp_req = content.splitlines()
        for line in decomp_req:
            line = line.decode('utf-8')
            if line.startswith("Package: "):
                pkg_name = re.search("^Package: (.*)", line).group(1)
            if line.startswith("Version: "):
                pkg_version = re.search("^Version: (.*)", line).group(1)
                check_pkg_name(pkg_name, pkg_version, codename, cve_dict, out_dict)
    else:
        for f in glob.glob(f"{repo_path}/**/*.deb", recursive=True):
            pkgv = os.path.basename(f).split("_")
            if len(pkgv) < 2: continue
            pkg_name = pkgv[0]
            pkg_version = pkgv[1]
            check_pkg_name(pkg_name, pkg_version, codename, cve_dict, out_dict)
    print (json.dumps(out_dict, indent=4))

if __name__ == "__main__":
    main()