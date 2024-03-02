# VUXML(3)

## NAME
vuxml - FreeBSD VuXML library

## SYNOPSIS
import **vuxml**

Dict *vuxml*.**load_vuxml**()

Dict *vuxml*.**get_vulns_by_topics**(Dict vuxml_data)

Dict *vuxml*.**get_vulns_by_packages**(Dict vuxml_data)

Dict *vuxml*.**get_vulns_by_references**(Dict vuxml_data)

Dict *vuxml*.**get_vulns_by_discovery_dates**(Dict vuxml_data)

Dict *vuxml*.**get_vulns_by_entry_dates**(Dict vuxml_data)

Dict *vuxml*.**get_vulns_by_modified_dates**(Dict vuxml_data)

List *vuxml*.**search_vulns_by_regex**(Dict vuxml_data, String regex_string, Boolean in_topics=True, Boolean in_descriptions=True)

List *vuxml*.**search_vulns_by_reference**(Dict vuxml_data, String source, String identifier)
 
List *vuxml*.**search_vulns_by_package**(Dict vuxml_data, String package_name, String package_version, Boolean regex_names=False)

Boolean *vuxml*.**is_valid_date**(String date_string)

List *vuxml*.**search_vulns_by_discovery_date**(Dict vuxml_data, String date_string)

List *vuxml*.**search_vulns_by_entry_date**(Dict vuxml_data, String date_string)

List *vuxml*.**search_vulns_by_modified_date**(Dict vuxml_data, String date_string)

Void *vuxml*.**print_vuln**(String vid, Dict vulnerability_data, Boolean show_description=False)

## DESCRIPTION
The **load_vuxml**() function downloads or reuse a FreeBSD VuXML library and returns it as a Python dictionary.

The **get_vulns_by_topics**() function returns a dictionary of vulnerabilities IDs (VID) by topics from a VuXML data structure.

The **get_vulns_by_packages**() function returns a dictionary of VID by packages/versions from a VuXML data structure.

The **get_vulns_by_references**() function returns a dictionary of VID by category/reference from a VuXML data structure.

The **get_vulns_by_discovery_dates**(), **get_vulns_by_discovery_dates**() and **get_vulns_by_discovery_dates**() functions
return a dictionary of VID by discovery, entry or modified dates from a VuXML data structure.

The **search_vulns_by_regex**() function returns a list of VID by regular expression in topics and/or descriptions.

The **search_vulns_by_reference**() function returns a list of VID by source & identifier in references.
At least one of the *source* and *identifier* parameters should be defined.

The **search_vulns_by_package**() function returns a list of VID by name & version in affects.
*package_name* is mandatory, *package_version* is optional.
*regex_names* indicates if the *package_name* is a regular expression.

The **is_valid_date**() function returns True if the given string is a recognized date format (ie. "YYYY-MM-DD", "YYYY-MM" or "YYYY").

The **search_vulns_by_discovery_date**() function returns a list of VID by date in discovery dates.

The **search_vulns_by_entry_date**() function returns a list of VID by date in entry dates.

The **search_vulns_by_modified_date**() function returns a list of VID by date in modified dates.

The **print_vuln**() function pretty prints a vulnerability from a VID and a vulnerability data structure.
The optional *show_description* parameter indicates if a text rendering of the description field (in HTML) is required.

## ENVIRONMENT
The *VUXML_DEBUG* environment variable can be set to any value to enable debug mode.

The *LOCALAPPDATA* and *TMP* environment variables under Windows, and *HOME*, *TMPDIR* and *TMP* environment variables
under other operating systems can influence the caching directory used.

## SEE ALSO
[vuxml(1)](https://github.com/HubTou/vuxml/blob/main/VUXML.1.md),
[VuXML website](https://www.vuxml.org/),
[FreeBSD VuXML website](https://www.vuxml.org/freebsd/),
[VuXML database explanation in the Porter's handbook](https://docs.freebsd.org/en/books/porters-handbook/security/),
[VuXML database as a FreeBSD port](https://www.freshports.org/security/vuxml/),
[pkg-audit(8)](https://man.freebsd.org/cgi/man.cgi?query=pkg-audit),
[vxquery](https://www.freshports.org/security/vxquery/)

## STANDARDS
The **vuxml** library is not a standard UNIX one.

It tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## HISTORY
This implementation was made for the [PNU project](https://github.com/HubTou/PNU).

While working on the [pipinfo(1)](https://github.com/HubTou/pipinfo) tool, I noticed that some Python packages installed as FreeBSD ports
where marked as vulnerable in [Python advisories](https://github.com/pypa/advisory-database) but not in [FreeBSD ports advisories](https://www.vuxml.org/freebsd/index.html).

I made a tool to check the 4000+ FreeBSD ports of Python packages, and found around 1% of them vulnerable.

So I made this library in order to verify if these vulnerable ports where also marked as vulnerable in FreeBSD VuXML,
and got carried away writing a full utility demonstrating its use!

## LICENSE
This library is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS)
[Hubert Tournier](https://github.com/HubTou)

## CAVEATS
[PORTREVISION and PORTEPOCH](https://people.freebsd.org/~olivierd/porters-handbook/makefile-naming.html) (ie. software versions ending with "\_number" or ",number")
are not taken into account when checking if a vulnerable Python package is also a vulnerable FreeBSD port.
I would have to develop my own versions comparison library in order to handle that (well, maybe one day :-) ).

