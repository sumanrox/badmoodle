import json
import os
from re import match

import requests
from bs4 import BeautifulSoup

from utils.output import *

# suppress requests insecure warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# dictionary for retrieving every moodle plugin path from its type
plugin_paths = {
    'assignsubmission' : '/mod/assign/submission/',
    'calendartype' : '/calendar/type/',
    'gradereport' : '/grade/report/',
    'assignfeedback' : '/assign/feedback/',
    'booktool' : '/mod/book/tool/',
    'workshopallocation' : '/mod/workshop/allocation/',
    'portfolio' : '/portfolio/',
    'message' : '/message/output/',
    'qtype' : '/question/type/',
    'availability' : '/availability/condition/',
    'contenttype' : '/contentbank/contenttype/',
    'media' : '/media/player/',
    'tinymce' : '/lib/editor/tinymce/plugins/',
    'quiz' : '/mod/quiz/report/',
    'profilefield' : '/user/profile/field/',
    'theme' : '/theme/',
    'ltisource' : '/mod/lti/source/',
    'editor' : '/lib/editor/',
    'quizaccess' : '/mod/quiz/accessrule/',
    'local' : '/local/',
    'cachestore' : '/cache/stores/',
    'repository' : '/repository/',
    'format' : '/course/format/',
    'qbehaviour' : '/question/behaviour/',
    'tool' : '/admin/tool/',
    'workshopeval' : '/mod/workshop/eval/',
    'antivirus' : '/lib/antivirus/',
    'dataformat' : '/dataformat/',
    'auth' : '/auth/',
    'report' : '/report/',
    'enrol' : '/enrol/',
    'mod' : '/mod/',
    'search' : '/search/engine/',
    'plagiarism' : '/plagiarism/',
    'webservice' : '/webservice/',
    'gradingform' : '/grade/grading/form/',
    'scormreport' : '/mod/scorm/report/',
    'gradeexport' : '/grade/export/',
    'fileconverter' : '/files/converter/',
    'filter' : '/filter/',
    'qformat' : '/question/format/',
    'datafield' : '/mod/data/field/',
    'logstore' : '/admin/tool/log/store/',
    'atto' : '/lib/editor/atto/plugins/',
    'paygw' : '/payment/gateway/',
    'customfield' : '/customfield/field/',
    'block' : '/blocks/'
}

# get an element's text from a table in a Moodle security advisory article
def get_element_table(trs, elem):
    return [tr.find_all('td')[1].get_text() for tr in trs if elem in tr.find_all('td')[0].get_text().lower()][0]


# parse CVEs from a table in a Moodle security advisory article
def parse_cves(trs):
    try:
        cvelist = [x for x in get_element_table(trs, 'cve identifier').split() if match('CVE-[0-9]{4}-[0-9]{0,8}', x)]
    except IndexError:
        try:
            cvelist = [x for x in get_element_table(trs, 'issue no').split() if match('CVE-[0-9]{4}-[0-9]{0,8}', x)]
        except IndexError:
            cvelist = ['N/A']

    if not cvelist:
        return ['N/A']

    return cvelist


# parse affected versions from a Moodle security advisory article
def parse_versions(unparsed):
    res = []

    unparsed = ' '.join(unparsed.split())
    elmts = [x.split(', ') for x in unparsed.split('and')]
    elmts = [y.replace('+','').replace(' only','').split('(')[0].strip() for x in elmts for y in x]

    if (len(elmts) == 1 and elmts[0].lower().startswith('all')) or (len(elmts) == 2 and elmts[0] == 'all past' and elmts[1] == 'future versions'):
        return [{'from':'0.0.0', 'to':'1.10.0'}]

    elmts += [x[2] for x in elmts if len(x.split('to')) > 2]

    for i, el in enumerate(elmts):
        if ')' in el:
            continue

        if 'unsupported versions' in el:
            res.append({'from':'0.0.0', 'to':res[-1]['from']})

        elif 'to' in el:
            if len(el.split('to')) > 2:
                continue
            res.append({'from':el.split(' to ')[0].replace('x','0'), 'to':el.split(' to ')[1].replace('x','99')})

        elif '-' in el:
            if len(el.split('-')) > 2:
                continue
            res.append({'from':el.split('-')[0].replace('x','0'), 'to':el.split('-')[1].replace('x','99')})

        elif '<' in el:
            if '=' in el:
                res.append({'from':'0.0.0', 'to':el.split('<=')[1].lstrip().replace('x','99')})
            else:
                res.append({'from':'0.0.0', 'to':el.split('<')[1].lstrip().replace('x','99')})
        else:
            res.append({'from':el.replace('x','0'), 'to':el.replace('x','99')})

    return res


# function to check and update a JSON file
def update_json(name, data, filename):
    # check if JSON file is up to date
    if os.path.isfile(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            before = json.load(f)
        if before == data:
            print_success(f'{name} is up to date')
            return 0

        # backup previous JSON file
        os.rename(filename, f'{filename}.old')
    else:
        before = []

    # write data to JSON file
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(data, jsonfile, indent=4)

    # return number of new entries on the updated JSON file
    return len(data) - len(before)


# update badmoodle official vulnerability database
def update_vulnerability_database(verbosity):
    print_status('Updating vulnerability database by scraping Moodle official security advisory blog')

    # getting pages and preparing vars
    url = 'https://moodle.org/security/index.php?o=3&p={}'
    try:
        r = requests.get('https://moodle.org/security/', timeout=15)
        r.raise_for_status()
        npages = int(r.text.split('<li class="page-item disabled" data-page-number="')[1].split('"')[0])
    except Exception as e:
        print_error('Error retrieving Moodle security pages count')
        if verbosity > 1:
            print_info(str(e))
        return
    vulnerability_database = []

    if verbosity > 1:
        print_status('Scraping {} pages from Moodle security advisory blog'.format(npages))

    # browse Moodle security advisory blog page by page
    for i in range(npages):
        if verbosity > 2:
            print_info('Scraping page {} of Moodle security advisory blog'.format(i + 1))

        # retrieve articles from every page
        r_page = requests.get(url.format(i), timeout=15)
        r_page.raise_for_status()
        for advisory in BeautifulSoup(r_page.text, 'html.parser').find_all('article'):
            try:
                trs = advisory.find('table').find_all('tr')
            except AttributeError:
                continue

            # extract all vulnerabilities info from articles
            title = advisory.find('h3', class_='h6').get_text()
            cves = parse_cves(trs)
            versions_affected = get_element_table(trs, 'versions affected').strip()
            versions = parse_versions(versions_affected)
            advisory_link = url.format(i) + '#' + advisory['id']

            # save vulnerability info into variable
            vulnerability_database.append(
                {
                    'title' : title,
                    'cves' : cves,
                    'versions' : versions,
                    'versions_affected' : versions_affected,
                    'link' : advisory_link
                }
            )

    # update JSON file
    new_entries = update_json('Vulnerability database', vulnerability_database, 'data/vulndb.json')

    if new_entries > 0:
        print_success(f'Vulnerability database successfully updated: {new_entries} new vulnerabilities added')

    if new_entries < 0:
        # something is wrong: maybe some vulnerabilities were removed from blog? or there are some parsing errors...
        raise Exception('JSON_ENTRIES_LESS_THAN_BEFORE')


# update badmoodle community vulnerability modules
def update_modules(verbosity):
    print_status('Retrieving new badmoodle community vulnerability modules from GitHub')

    # retrieve modules list using GitHub API
    try:
        r = requests.get('https://api.github.com/repos/cyberaz0r/badmoodle/git/trees/main', timeout=10)
        r.raise_for_status()
        tree = r.json().get('tree', [])
        modules_url = [x['url'] for x in tree if x.get('path') == 'vulns'][0]

        r2 = requests.get(modules_url, timeout=10)
        r2.raise_for_status()
        modules_list = [x['path'] for x in r2.json().get('tree', []) if x.get('path', '').endswith('.py')]
    except Exception as e:
        print_error('Update failed: error while retrieving online modules list\n')
        if verbosity > 1:
            print_info(str(e))
        return False

    # check new modules
    already_existing_modules = [x for x in os.listdir('vulns') if x.endswith('.py')]
    new_modules = [x for x in modules_list if x not in already_existing_modules]

    if not new_modules:
        print_success('All new badmoodle community vulnerability modules are already installed\n')
        return True

    if verbosity > 1:
        print_info(f'Found {len(new_modules)} new community vulnerability modules')

    # download and install new modules
    for module in new_modules:
        if verbosity > 1:
            print_status(f'Installing new community vulnerability module "{module[:-3]}"')
        try:
            new_module_content = requests.get(f'https://raw.githubusercontent.com/cyberaz0r/badmoodle/master/vulns/{module}').text
            with open(f'vulns/{module}', 'w', encoding='utf-8') as new_module:
                new_module.write(new_module_content)
        except Exception:
            print_error(f'Update failed: error while installing module "{module}"\n')
            return False

        if verbosity > 1:
            print_success(f'Successfully installed new community vulnerability module "{module[:-3]}"')

    print_success(f'Update successful: {len(new_modules)} new modules added\n')
    return True


# update plugin and theme list
def update_plugin_list(verbosity):
    plugins = []
    i = 0

    print_status('Updating plugin and themes list by using moodle.org API')

    while True:
        if verbosity > 2:
            print_info(f'Retrieving plugin/themes list from moodle.org API (page {i + 1})')

        data = json.loads(
            requests.post(
                'https://moodle.org/lib/ajax/service.php',
                json = [{'index' : 0, 'methodname' : 'local_plugins_get_plugins_batch', 'args' : {'query' : '', 'batch' : i}}]
            ).text
        )

        # loop until API results are empty
        if not data[0]['data']['grid']['plugins']:
            break

        # append results to list
        for plugin in data[0]['data']['grid']['plugins']:
            # append only plugins with known path
            if plugin['plugintype']['type'] in plugin_paths.keys():
                plugins.append(
                    {
                        'id' : plugin['id'],
                        'type' : plugin['plugintype']['type'],
                        'name' : plugin['name'],
                        'description' : plugin['shortdescription'],
                        'url' : plugin['url'],
                        'path' : f"{plugin_paths[plugin['plugintype']['type']]}{plugin['url'].replace('https://moodle.org/plugins/' + plugin['plugintype']['type'] + '_', '')}/"
                    }
                )

        i += 1

    # update JSON file
    new_entries = update_json('Plugin list', plugins, 'data/plugins.json')

    if new_entries > 0:
        print_success(f'Plugin list successfully updated: {new_entries} new plugins added')

    if new_entries < 0:
        # something is wrong: maybe some plugins were removed? or there are some parsing errors...
        raise Exception('JSON_ENTRIES_LESS_THAN_BEFORE')
