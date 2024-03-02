#!/usr/bin/env python3
""" vuxml - FreeBSD VuXML library and query tool
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import getopt
import logging
import os
import re
import sys
import uuid

import libpnu

from .library import load_vuxml, get_vulns_by_topics, get_vulns_by_packages, \
                     get_vulns_by_references, get_vulns_by_discovery_dates, \
                     get_vulns_by_entry_dates, get_vulns_by_modified_dates, search_vulns_by_regex, \
                     search_vulns_by_reference, search_vulns_by_package, is_valid_date, \
                     search_vulns_by_discovery_date, search_vulns_by_entry_date, \
                     search_vulns_by_modified_date, print_vuln

# Version string used by the what(1) and ident(1) commands:
ID = "@(#) $Id: vuxml - FreeBSD VuXML library and query tool v1.0.2 (March 2, 2024) by Hubert Tournier $"

# Default parameters. Can be overcome by environment variables, then command line options
parameters = {
    "Vid": [],
    "Topics": [],
    "Packages": [],
    "Keywords": [],
    "References": [],
    "Discovery dates": [],
    "Entry dates": [],
    "Modified dates": [],
    "Regex names": False,
    "List references sources": False,
    "Print description": False,
}


####################################################################################################
def _display_help():
    """ Display usage and help """
    #pylint: disable=C0301
    print("usage: vuxml [--desc|-D] [--id|-i VID]", file=sys.stderr)
    print("       [--topic|-t RE] [--keyword|-k]", file=sys.stderr)
    print("       [--package|-p PID] [--re-names|-R]", file=sys.stderr)
    print("       [--sources|-s] [--ref|-r RID]", file=sys.stderr)
    print("       [--discovery|-d DATE] [--entry|-e DATE] [--modified|-m DATE]", file=sys.stderr)
    print("       [--debug] [--help|-?] [--version] [--]", file=sys.stderr)
    print("  -------------------  --------------------------------------------------", file=sys.stderr)
    print("  --desc|-D            Print description", file=sys.stderr)
    print("  --id|-i VID          Search for the specified Vulnerability ID", file=sys.stderr)
    print("  --topic|-t RE        Search for the specified regex in topics", file=sys.stderr)
    print("  --keyword|-k RE      Search for the specified regex in topics and desc.", file=sys.stderr)
    print("  --package|-p PID     Search for the specified name in affected packages", file=sys.stderr)
    print("                       PID can also be name~version", file=sys.stderr)
    print("  --re-names|-R        The name part of a PID is a regex", file=sys.stderr)
    print("  --sources|-s         List references sources", file=sys.stderr)
    print("  --ref|-r RID         Search for the specified ID in references", file=sys.stderr)
    print("                       RID can also be source~, source~ID", file=sys.stderr)
    print("  --discovery|-d DATE  Search for the specified date in discovery dates", file=sys.stderr)
    print("  --entry|-e DATE      Search for the specified date in entry dates", file=sys.stderr)
    print("  --modified|-m DATE   Search for the specified date in modified dates", file=sys.stderr)
    print("                       DATE can be YYYY-MM-DD, YYYY-MM or YYYY", file=sys.stderr)
    print("  --debug              Enable debug mode", file=sys.stderr)
    print("  --help|-?            Print usage and this help message and exit", file=sys.stderr)
    print("  --version            Print version and exit", file=sys.stderr)
    print("  --                   Options processing terminator", file=sys.stderr)
    print(file=sys.stderr)
    #pylint: enable=C0301


####################################################################################################
def _handle_interrupts(signal_number, current_stack_frame):
    """ Prevent SIGINT signals from displaying an ugly stack trace """
    print(" Interrupted!\n", file=sys.stderr)
    sys.exit(0)


####################################################################################################
def _process_environment_variables():
    """ Process environment variables """
    #pylint: disable=C0103, W0602
    global parameters
    #pylint: enable=C0103, W0602

    if "VUXML_DEBUG" in os.environ:
        logging.disable(logging.NOTSET)

    logging.debug("_process_environment_variables(): parameters:")
    logging.debug(parameters)


####################################################################################################
def _process_command_line():
    """ Process command line options """
    #pylint: disable=C0103, W0602
    global parameters
    #pylint: enable=C0103, W0602

    # option letters followed by : expect an argument
    # same for option strings followed by =
    character_options = "d:e:i:k:m:p:r:st:DR?"
    string_options = [
        "debug",
        "description",
        "discovery=",
        "entry=",
        "help",
        "id=",
        "keyword=",
        "modified=",
        "package=",
        "ref=",
        "re-names",
        "sources",
        "topic=",
        "version",
    ]

    try:
        options, remaining_arguments = getopt.getopt(
            sys.argv[1:], character_options, string_options
        )
    except getopt.GetoptError as error:
        logging.critical("Syntax error: %s", error)
        _display_help()
        sys.exit(1)

    for option, argument in options:

        if option == "--debug":
            logging.disable(logging.NOTSET)

        elif option in ("--help", "-?"):
            _display_help()
            sys.exit(0)

        elif option == "--version":
            print(ID.replace("@(" + "#)" + " $" + "Id" + ": ", "").replace(" $", ""))
            sys.exit(0)

        elif option in ["--desc", "-D"]:
            parameters['Print description'] = True

        elif option in ["--discovery", "-d"]:
            if not is_valid_date(argument):
                logging.error('--discovery argument is not a valid date')
                continue

            parameters['Discovery dates'].append(argument)

        elif option in ["--entry", "-e"]:
            if not is_valid_date(argument):
                logging.error('--entry argument is not a valid date')
                continue

            parameters['Entry dates'].append(argument)

        elif option in ["--id", "-i"]:
            try:
                vid = uuid.UUID(argument)
            except ValueError:
                logging.error('--id argument is not a valid UUID')
                continue

            if argument not in parameters['Vid']:
                parameters['Vid'].append(str(vid))

        elif option in ["--keyword", "-k"]:
            try:
                _ = re.compile(argument)
            except re.error as error:
                logging.error('--keyword argument is not a valid regular expression: %s', error)
                continue

            if argument not in parameters['Keywords']:
                parameters['Keywords'].append(argument)

        elif option in ["--modified", "-m"]:
            if not is_valid_date(argument):
                logging.error('--modified argument is not a valid date')
                continue

            parameters['Modified dates'].append(argument)

        elif option in ["--package", "-p"]:
            if len(argument.split('~')) > 2:
                logging.error("--package argument can contain only one '~' character")
                continue

            if argument not in parameters['Packages']:
                parameters['Packages'].append(argument)

        elif option in ["--ref", "-r"]:
            if len(argument.split('~')) > 2:
                logging.error("--ref argument can contain only one '~' character")
                continue

            if argument not in parameters['References']:
                parameters['References'].append(argument)

        elif option in ["--re-names", "-R"]:
            parameters["Regex names"] = True

        elif option in ["--sources", "-s"]:
            parameters["List references sources"] = True

        elif option in ["--topic", "-t"]:
            try:
                _ = re.compile(argument)
            except re.error as error:
                logging.error('--topic argument is not a valid regular expression: %s', error)
                continue

            if argument not in parameters['Topics']:
                parameters['Topics'].append(argument)

    logging.debug("_process_command_line(): parameters:")
    logging.debug(parameters)
    logging.debug("_process_command_line(): remaining_arguments:")
    logging.debug(remaining_arguments)

    return remaining_arguments


####################################################################################################
def main():
    """ The program's main entry point """
    program_name = os.path.basename(sys.argv[0])

    libpnu.initialize_debugging(program_name)
    libpnu.handle_interrupt_signals(_handle_interrupts)
    _process_environment_variables()
    _ = _process_command_line()

    done_nothing = True
    vulns_count = 0

    vuxml = load_vuxml()

    if parameters['Vid']:
        done_nothing = False
        for vid in parameters['Vid']:
            if vid in vuxml:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['Topics']:
        done_nothing = False
        for regex_string in parameters['Topics']:
            vulns = search_vulns_by_regex(
                vuxml,
                regex_string,
                in_topics=True,
                in_descriptions=False
            )
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['Keywords']:
        done_nothing = False
        for regex_string in parameters['Keywords']:
            vulns = search_vulns_by_regex(vuxml, regex_string, in_topics=True, in_descriptions=True)
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['Packages']:
        done_nothing = False
        for package in parameters['Packages']:
            if '~' in package:
                name = package.split('~')[0]
                version = package.split('~')[1]
            else:
                name = package
                version = ''
            vulns = search_vulns_by_package(
                vuxml,
                name,
                version,
                regex_names=parameters['Regex names']
            )
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['References']:
        done_nothing = False
        for reference in parameters['References']:
            if '~' in reference:
                source = reference.split('~')[0]
                identifier = reference.split('~')[1]
            else:
                source = ''
                identifier = reference
            vulns = search_vulns_by_reference(vuxml, source, identifier)
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['Discovery dates']:
        done_nothing = False
        for date in parameters['Discovery dates']:
            vulns = search_vulns_by_discovery_date(vuxml, date)
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['Entry dates']:
        done_nothing = False
        for date in parameters['Entry dates']:
            vulns = search_vulns_by_entry_date(vuxml, date)
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if parameters['Modified dates']:
        done_nothing = False
        for date in parameters['Modified dates']:
            vulns = search_vulns_by_modified_date(vuxml, date)
            for vid in vulns:
                print_vuln(vid, vuxml[vid], show_description=parameters['Print description'])
                vulns_count += 1

    if vulns_count:
        if vulns_count == 1:
            print("1 vulnerability found")
        else:
            print(f"{vulns_count} vulnerabilities found")

    if parameters['List references sources']:
        done_nothing = False
        references = get_vulns_by_references(vuxml)
        print("References sources:")
        for source in references.keys():
            if source == 'bid':
                print("  bid - SecurityFocus Bug ID")
            elif source == 'certsa':
                print("  certsa - US-CERT security advisory")
            elif source == 'certvu':
                print("  certvu - US-CERT vulnerability note")
            elif source == 'cvename':
                print("  cvename - Mitre CVE identifier")
            elif source == 'freebsdpr':
                print("  freebsdpr - FreeBSD problem report")
            elif source == 'freebsdsa':
                print("  freebsdsa - FreeBSD security advisory")
            elif source == 'mlist':
                print("  mlist - URL to an archived posting in a mailing list")
            elif source == 'url':
                print("  url - Generic URL")
            elif source == 'uscertsa':
                print("  uscertta - US-CERT cyber security alert")
            elif source == 'uscertta':
                print("  uscertta - US-CERT technical cyber security alert")
            else:
                print(f"  {source} - ?")
        print()

    if done_nothing:
        _display_help()

    sys.exit(0)


if __name__ == "__main__":
    main()
