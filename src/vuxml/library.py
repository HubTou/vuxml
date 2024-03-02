#!/usr/bin/env python3
""" vuxml - FreebSD VuXML manipulation library
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import datetime
import logging
import lzma
import os
import re
import time
import urllib.request

import colorama
import defusedxml.ElementTree
import html2text
import packaging.version


####################################################################################################
def _download_vuxml():
    """ Download and cache the latest FreeBSD VuXML version """
    # Where do we want to cache the file
    filename = ''
    directory = ''
    if os.name == 'nt':
        if 'LOCALAPPDATA' in os.environ:
            directory = os.environ['LOCALAPPDATA'] + os.sep + "cache" + os.sep + "vuxml"
        elif 'TMP' in os.environ:
            directory = os.environ['TMP'] + os.sep + "vuxml"
    else: # os.name == 'posix':
        if 'HOME' in os.environ:
            directory = os.environ['HOME'] + os.sep + ".cache" + os.sep + "vuxml"
        elif 'TMPDIR' in os.environ:
            directory = os.environ['TMPDIR'] + os.sep + "vuxml"
        elif 'TMP' in os.environ:
            directory = os.environ['TMP'] + os.sep + "vuxml"
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            directory = ''
    if directory:
        filename = directory + os.sep + 'vuln.xml'
    else:
        filename = 'vuln.xml'

    # If there's a caching file of less than 1 day, use it
    if filename \
    and os.path.isfile(filename) \
    and (time.time() - os.path.getmtime(filename)) < 24 * 60 * 60:
        return filename

    # Download the latest version
    url = 'https://www.vuxml.org/freebsd/vuln.xml.xz'
    try:
        with urllib.request.urlopen(url) as http:
            xz_data = http.read()
    except urllib.error.HTTPError as error:
        logging.error("Error while fetching '%s': %s", url, error)
        return ''

    # Uncompress the data
    data = lzma.decompress(xz_data)
    with open(filename, "w", encoding='utf-8') as file:
        for line in data.decode('utf-8', errors='ignore').split('\n'):
            if not(line.startswith('<!DOCTYPE') \
            or line.startswith('<!ENTITY') \
            or line.startswith(']>')):
                file.write(line + '\n')

    return filename


####################################################################################################
def _get_sub_description(node):
    """ Concatenate the current and sub levels description tags in a single string """
    description = ""

    for element in node:
        tag = re.sub(r'{[^}]*}', '', element.tag)
        if element.attrib:
            description += f"<{tag}"
            for key, value in element.attrib.items():
                description += f' {key}="{value}"'
            description += '>'
        else:
            description += f"<{tag}>"

        if element.text is not None:
            text = re.sub(r"\n[ \t]*", " ", element.text)
            text = re.sub(r"\t+", " ", text)
            description += text

        description += _get_sub_description(element) + f"</{tag}>"

    return description


####################################################################################################
def load_vuxml():
    """ Return a Python data structure from a FreeBSD VuXML file """
    filename = _download_vuxml()

    tree = defusedxml.ElementTree.parse(filename)
    root = tree.getroot()

    vuxml = {}
    for vuln in root:
        vuln_vid = vuln.attrib['vid']
        vuxml[vuln_vid] = {}

        for element1 in vuln:
            tag1 = re.sub(r'{[^}]*}', '', element1.tag)
            if tag1 == 'topic':
                vuxml[vuln_vid]['topic'] = element1.text.strip()
                continue
            elif tag1 == 'affects':
                vuxml[vuln_vid]['affects'] = {}
            elif tag1 == 'description':
                vuxml[vuln_vid]['description'] = ""
            elif tag1 == 'references':
                vuxml[vuln_vid]['references'] = []
            elif tag1 == 'dates':
                vuxml[vuln_vid]['dates'] = {}
            elif tag1 == 'cancelled':
                del vuxml[vuln_vid]
                continue
            else:
                logging.warning("Unknown tag: %s", tag1)

            description = ""
            for element2 in element1:
                tag2 = re.sub(r'{[^}]*}', '', element2.tag)
                if element2.text is not None:
                    text = element2.text.strip()
                else:
                    text = ''

                if tag1 == 'affects':
                    names = []
                    ranges = []
                    for element3 in element2:
                        tag3 = re.sub(r'{[^}]*}', '', element3.tag)
                        if tag3 == 'name':
                            names.append(element3.text)
                        elif tag3 == 'range':
                            version = []
                            for element4 in element3:
                                tag4 = re.sub(r'{[^}]*}', '', element4.tag)
                                if tag4 == 'lt':
                                    version.append(['<', f'{element4.text}'])
                                elif tag4 == 'le':
                                    version.append(['<=', f'{element4.text}'])
                                elif tag4 == 'eq':
                                    version.append(['==', f'{element4.text}'])
                                elif tag4 == 'ge':
                                    version.append(['>=', f'{element4.text}'])
                                elif tag4 == 'gt':
                                    version.append(['>', f'{element4.text}'])
                            ranges.append(version)
                    for name in names:
                        vuxml[vuln_vid]['affects'][name] = ranges

                elif tag1 == 'description':
                    description += _get_sub_description(element2)

                elif tag1 == 'references':
                    vuxml[vuln_vid]['references'].append({tag2: text})

                elif tag1 == 'dates':
                    vuxml[vuln_vid]['dates'][tag2] = text

            if description:
                vuxml[vuln_vid]['description'] = description

    return vuxml


####################################################################################################
def get_vulns_by_topics(vuxml):
    """ Return a dictionary of VID by topics from a VuXML data structure """
    if not vuxml:
        return {}

    topics = {}
    for vuln_vid, vuln_data in vuxml.items():
        if vuln_data['topic'] in topics:
            topics[vuln_data['topic']].append(vuln_vid)
        else:
            topics[vuln_data['topic']] = [vuln_vid]

    return topics


####################################################################################################
def get_vulns_by_packages(vuxml):
    """ Return a dictionary of VID by packages/versions from a VuXML data structure """
    if not vuxml:
        return {}

    packages = {}
    for vuln_vid, vuln_data in vuxml.items():
        for package, version_ranges in vuln_data['affects'].items():
            for version_range in version_ranges:
                if package in packages:
                    packages[package].append([version_range, vuln_vid])
                else:
                    packages[package] = [[version_range, vuln_vid]]

    return packages


####################################################################################################
def get_vulns_by_references(vuxml):
    """ Return a dictionary of VID by category/reference from a VuXML data structure """
    if not vuxml:
        return {}

    references = {}
    for vuln_vid, vuln_data in vuxml.items():
        for reference in vuln_data['references']:
            for key, value in reference.items():
                if key in references:
                    if  value in references[key]:
                        references[key][value].append(vuln_vid)
                    else:
                        references[key][value] = [vuln_vid]
                else:
                    references[key] = {}
                    references[key][value] = [vuln_vid]

    return references


####################################################################################################
def get_vulns_by_discovery_dates(vuxml):
    """ Return a dictionary of VID by discovery dates from a VuXML data structure """
    if not vuxml:
        return {}

    discovery_dates = {}
    for vuln_vid, vuln_data in vuxml.items():
        if 'discovery' in vuln_data['dates']:
            if vuln_data['dates']['discovery'] in discovery_dates:
                discovery_dates[vuln_data['dates']['discovery']].append(vuln_vid)
            else:
                discovery_dates[vuln_data['dates']['discovery']] = [vuln_vid]

    return discovery_dates


####################################################################################################
def get_vulns_by_entry_dates(vuxml):
    """ Return a dictionary of VID by entry dates from a VuXML data structure """
    if not vuxml:
        return {}

    entry_dates = {}
    for vuln_vid, vuln_data in vuxml.items():
        if 'entry' in vuln_data['dates']:
            if vuln_data['dates']['entry'] in entry_dates:
                entry_dates[vuln_data['dates']['entry']].append(vuln_vid)
            else:
                entry_dates[vuln_data['dates']['entry']] = [vuln_vid]

    return entry_dates


####################################################################################################
def get_vulns_by_modified_dates(vuxml):
    """ Return a dictionary of VID by modified dates from a VuXML data structure """
    if not vuxml:
        return {}

    modified_dates = {}
    for vuln_vid, vuln_data in vuxml.items():
        if 'modified' in vuln_data['dates']:
            if vuln_data['dates']['modified'] in modified_dates:
                modified_dates[vuln_data['dates']['modified']].append(vuln_vid)
            else:
                modified_dates[vuln_data['dates']['modified']] = [vuln_vid]

    return modified_dates


####################################################################################################
def search_vulns_by_regex(vuxml, regex_string, in_topics=True, in_descriptions=True):
    """ Return a list of VID by regex in topics and/or descriptions """
    if not vuxml:
        return []

    try:
        regex = re.compile(regex_string)
    except re.error as error:
        logging.error(
            "search_vulns_by_regex() argument is not a valid regular expression: %s",
            error
        )
        return []

    vulns = []
    for vuln_vid, vuln_data in vuxml.items():
        if in_topics and 'topic' in vuln_data:
            if re.search(regex, vuln_data['topic']):
                vulns.append(vuln_vid)
        if in_descriptions and 'description' in vuln_data:
            if re.search(regex, vuln_data['description']):
                if vuln_vid not in vulns:
                    vulns.append(vuln_vid)

    return vulns


####################################################################################################
def search_vulns_by_reference(vuxml, source, identifier):
    """ Return a list of VID by source & identifier in references """
    if not vuxml:
        return []

    vulns = []
    references = get_vulns_by_references(vuxml)
    for key, value in references.items():
        if not source or source == key:
            for subkey, subvalue in value.items():
                if not identifier or subkey == identifier:
                    for vid in subvalue:
                        vulns.append(vid)

    return vulns


####################################################################################################
def search_vulns_by_package(vuxml, package_name, package_version, regex_names=False):
    """ Return a list of VID by name & version in affects """
    if not vuxml:
        return []

    vulns = []
    packages = get_vulns_by_packages(vuxml)
    for name, version_ranges in packages.items():
        if (regex_names and re.search(package_name, name)) \
        or name == package_name:
            for version_range in version_ranges:
                vid = version_range[1]
                # If no version is specified, we return all the VID for the name
                if not package_version:
                    if vid not in vulns:
                        vulns.append(vid)
                else:
                    package_version2 = packaging.version.parse(package_version)

                    conditions = version_range[0]
                    test_results = True
                    for condition in conditions:
                        operator = condition[0]
                        affected_version = condition[1]

                        # CAVEAT:
                        # The packaging module doesn't know how to handle some version numbers
                        # (it's made only for Python packages versions)
                        # I should write my own!
                        try:
                            affected_version2 = packaging.version.parse(affected_version)
                        except packaging.version.InvalidVersion:
                            altered_affected_version = re.sub(r"_.*", "", affected_version)
                            altered_affected_version = re.sub(r",.*", "", altered_affected_version)
                            altered_affected_version = re.sub(r"\.\*", "", altered_affected_version)
                            logging.debug(
                                "Version number '%s' handled as '%s'",
                                affected_version,
                                altered_affected_version
                            )
                            affected_version2 = packaging.version.parse(altered_affected_version)

                        if operator == '>':
                            if package_version2 <= affected_version2:
                                test_results = False
                                break
                        elif operator == '>=':
                            if package_version2 < affected_version2:
                                test_results = False
                                break
                        elif operator == '==':
                            if package_version2 != affected_version2:
                                test_results = False
                                break
                        elif operator == '<=':
                            if package_version2 > affected_version2:
                                test_results = False
                                break
                        elif operator == '<':
                            if package_version2 >= affected_version2:
                                test_results = False
                                break
                        else:
                            logging.warning("Unknown operator: %s", operator)
                            test_results = False
                            break
                    if test_results:
                        if vid not in vulns:
                            vulns.append(vid)

    return vulns


####################################################################################################
def is_valid_date(string):
    """ Return True if string is a recognized date format """
    parts = string.split('-')
    if len(parts) > 3:
        return False

    try:
        year = int(parts[0])
    except ValueError:
        return False
    if year < 1970 or len(parts[0]) != 4:
        return False

    month = 1
    if len(parts) >= 2:
        try:
            month = int(parts[1])
        except ValueError:
            return False
        if not (1 <= month <= 12) or len(parts[1]) != 2:
            return False

    day = 1
    if len(parts) == 3:
        try:
            day = int(parts[2])
        except ValueError:
            return False
        if not (1 <= day <= 31) or len(parts[2]) != 2:
            return False

    try:
        _ = datetime.datetime(year, month, day)
    except ValueError:
        return False

    return True


####################################################################################################
def search_vulns_by_discovery_date(vuxml, date):
    """ Return a list of VID by date in discovery dates """
    if not vuxml or not is_valid_date(date):
        return []

    vulns = []
    discovery_dates = get_vulns_by_discovery_dates(vuxml)
    for key, value in discovery_dates.items():
        if key.startswith(date):
            for vid in value:
                if vid not in vulns:
                    vulns.append(vid)

    return vulns


####################################################################################################
def search_vulns_by_entry_date(vuxml, date):
    """ Return a list of VID by date in entry dates """
    if not vuxml or not is_valid_date(date):
        return []

    vulns = []
    entry_dates = get_vulns_by_entry_dates(vuxml)
    for key, value in entry_dates.items():
        if key.startswith(date):
            for vid in value:
                if vid not in vulns:
                    vulns.append(vid)

    return vulns


####################################################################################################
def search_vulns_by_modified_date(vuxml, date):
    """ Return a list of VID by date in modified dates """
    if not vuxml or not is_valid_date(date):
        return []

    vulns = []
    modified_dates = get_vulns_by_modified_dates(vuxml)
    for key, value in modified_dates.items():
        if key.startswith(date):
            for vid in value:
                if vid not in vulns:
                    vulns.append(vid)

    return vulns


####################################################################################################
def print_vuln(vid, vuln, show_description=False):
    """ Pretty print a vulnerability """
    colorama.init()
    bright = colorama.Style.BRIGHT
    red = colorama.Fore.RED
    red_bg = colorama.Back.RED
    normal = colorama.Style.RESET_ALL
    print(f"{bright}Vulnerability ID:{normal} {vid}")
    if 'topic' in vuln:
        print(f"  {bright}Topic:{normal} {red_bg}{vuln['topic']}{normal}")
    if 'affects' in vuln:
        print(f"  {bright}Affects:{normal}")
        for package_name, package_version_ranges in vuln['affects'].items():
            print(f"    {bright}{red}{package_name}{normal}:")
            for package_version_range in package_version_ranges:
                print("      ", end="")
                for condition in package_version_range:
                    print(f"{condition[0]} {condition[1]} ; ", end="")
                print()
    if show_description and 'description' in vuln:
        print(f"  {bright}Description:{normal}")
        text_maker = html2text.HTML2Text()
        text_maker.ignore_links = True
        text_maker.bypass_tables = False
        text = text_maker.handle(vuln['description'])
        for line in text.split('/n'):
            print(f"    {line}")
    if 'references' in vuln:
        if len(vuln['references']):
            print(f"  {bright}References:{normal}")
            for reference in vuln['references']:
                for key, value in reference.items():
                    print(f"    {key}: {value}")
    if 'dates' in vuln:
        if 'discovery' in vuln['dates']:
            print(f"  {bright}Discovery date:{normal} {vuln['dates']['discovery']}")
        if 'entry' in vuln['dates']:
            print(f"  {bright}Entry date:{normal} {vuln['dates']['entry']}")
        if 'modified' in vuln['dates']:
            print(f"  {bright}Modified date:{normal} {vuln['dates']['modified']}")
    print()
