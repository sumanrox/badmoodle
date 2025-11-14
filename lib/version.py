import json
from hashlib import md5

import requests

from utils.output import *

# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_moodle(url, sess):
    # checking if valid url
    try:
        urlcheck = sess.get(url)
        urlcheck.raise_for_status()
    except requests.exceptions.RequestException:
        print_error('Error: invalid URL')
        print_error('Terminating badmoodle due to errors', True)
        return False

    # checking if valid moodle instance and return version or False otherwise
    try:
        moodlecheck1 = sess.get(f'{url}/lib/editor/atto/lib.php', timeout=10)
        moodlecheck2 = sess.get(f'{url}/course/view.php', timeout=10)
    except requests.exceptions.RequestException:
        print_error('Error: unable to reach Moodle endpoints')
        print_error('Terminating badmoodle due to errors', True)
        return False

    if moodlecheck1.status_code == 200 and not moodlecheck1.text and '/error/moodle/unspecifycourseid' in moodlecheck2.text:
        moodle_ver = moodlecheck2.text.split('/error/moodle/unspecifycourseid')[0].split('docs.moodle.org/')[-1].split('/')[0]
        return f'v{moodle_ver[0]}.{moodle_ver[1:]}'

    print_error('Error: the URL specified does not refer to a moodle instance')
    print_error('Terminating badmoodle due to errors', True)
    return False


# retrieve more granular moodle version by confronting file hashes of specific versions
def get_moodle_specific_version(url, sess, verbosity):
    files = [
        '/admin/environment.xml', '/composer.lock', '/lib/upgrade.txt', '/privacy/export_files/general.js',
        '/composer.json', '/question/upgrade.txt', '/admin/tool/lp/tests/behat/course_competencies.feature'
    ]

    try:
        r = requests.get('https://raw.githubusercontent.com/inc0d3/moodlescan/master/data/version.txt', timeout=10)
        r.raise_for_status()
        versions = [{'ver':x.split(';')[0], 'hash':x.split(';')[1], 'file':x.split(';')[2]} for x in r.text.splitlines()]
    except requests.exceptions.RequestException:
        return False

    for f in files:
        try:
            file_resp = sess.get(f'{url}{f}', timeout=10)
            filehash = md5(file_resp.text.encode('utf-8')).hexdigest()
            version = [x for x in versions if filehash == x['hash']]

            if len(version) == 1:
                if verbosity > 1:
                    print_success(f'Determined Moodle version through file "{version[0]["file"]}"')
                return version[0]['ver']
        except requests.exceptions.RequestException:
            continue

    return False


# check if a version is in a range by confronting the concatenation of major, minor and patch (forcing 2 ciphers each) converted to integer
def check_in_range(ver, vuln_ver):
    ver = int(''.join([str(x).zfill(2) for x in ver.split('.')]))
    ver_from = int(''.join([str(x).zfill(2) for x in vuln_ver['from'].split('.')]))
    ver_to = int(''.join([str(x).zfill(2) for x in vuln_ver['to'].split('.')]))
    return (ver >= ver_from and ver <= ver_to)


# retrieve all the vulnerabilities that affect a specific version
def list_vulnerabilities(ver):
    if len(ver.split('.')) < 3:
        ver += '.0'

    vulnerabilities_found = []
    with open('data/vulndb.json', 'r', encoding='utf-8') as f:
        vulnerability_database = json.load(f)

    for vuln in vulnerability_database:
        for vuln_ver in vuln['versions']:
            if check_in_range(ver, vuln_ver):
                vulnerabilities_found.append(vuln)
                break

    return vulnerabilities_found
