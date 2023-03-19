# VUXML(1)

## NAME
vuxml - FreeBSD VuXML query tool

## SYNOPSIS
**vuxml**
\[--desc|-D\]
\[--id|-i VID\]
\[--topic|-t RE\]
\[--keyword|-k RE\]
\[--package|-p PID\]
\[--re-names|-R\]
\[--sources|-s\]
\[--ref|-r RID\]
\[--discovery|-d DATE\]
\[--entry|-e DATE\]
\[--modified|-m DATE\]
\[--debug\]
\[--help|-?\]
\[--version\]
\[--\]

## DESCRIPTION
The **vuxml** utility provides easy and flexible ways to query the FreeBSD VuXML database of security issues in FreeBSD and its ports collection.

You can search or explore the database:
* by vulnerability ID (with the *--id|-i* option),
* by regular expression in topics (with the *--topic|-t* option),
* by regular expression in topics and descriptions (with the *--keyword|-k* option),
* by package name or package name and version (with the *--package|-p* option),
  * the package name can be treated as a regular expression (with the *--re-names|-R* option),
* by reference source, reference source and ID, or ID (with the *--ref|-r* option),
  * existing sources can be listed (with the *--sources|-s* option),
* by discovery, entry or modification dates (with the *--discovery|-d*, *--entry|-e* or *--modified|-m* options),
  * these dates can be a specific day, month or year.

For all these queries the detailed description is not printed, unless you use the *--desc|-d* option to render the HTML description as text.

For the package and reference queries, the package and version, or reference source and ID, are separated using the '~' character.

All the options can be used several times and their results are cumulative (ie. treated as logical OR).

### OPTIONS
Options | Use
------- | ---
--desc\|-D|Print description
--id\|-i VID|Search for the specified Vulnerability ID
--topic\|-t RE|Search for the specified regex in topics
--keyword\|-k RE|Search for the specified regex in topics and desc.
--package\|-p PID|Search for the specified name in affected packages. PID can also be name~version
--re-names\|-R|The name part of a PID is a regex
--sources\|-s|List references sources
--ref\|-r RID|Search for the specified ID in references. RID can also be source~, source~ID
--discovery\|-d DATE|Search for the specified date in discovery dates
--entry\|-e DATE|Search for the specified date in entry dates
--modified\|-m DATE|Search for the specified date in modified dates. DATE can be YYYY-MM-DD, YYYY-MM or YYYY
--debug|Enable debug mode
--help\|-?|Print usage and a short help message and exit
--version|Print version and exit
--|Options processing terminator

## ENVIRONMENT
The *VUXML_DEBUG* environment variable can be set to any value to enable debug mode.

The *LOCALAPPDATA* and *TMP* environment variables under Windows, and *HOME*, *TMPDIR* and *TMP* environment variables
under other operating systems can influence of the caching directory used.

## FILES
The *vuxml* utility will attempt to maintain a caching directory for the web service it uses, where the downloaded database will be re-used within the next 24 hours.

This directory will be located in one of the following places:

    Windows:
        %LOCALAPPDATA%\cache\vuxml
        %TMP%\cache\vuxml
    Unix:
        ${HOME}/.cache/vuxml
        ${TMPDIR}/.cache/vuxml
        ${TMP}/.cache/vuxml

## EXIT STATUS
The **vuxml** utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES
Use the following command to search for vulnerabilities affecting the "gnutls" package:
```
vuxml -p gnutls
```

And the following one to search for vulnerabilities affecting packages whose name starts with "gnutls" ("gnutls", "gnutls-devel", "gnutls3" will match, while "linux-f10-gnutls" won't):
```
vuxml -Rp "^gnutls"
```

## SEE ALSO
[vuxml(3)](https://github.com/HubTou/vuxml/blob/main/VUXML.3.md),
[VuXML website](https://www.vuxml.org/),
[FreeBSD VuXML website](https://www.vuxml.org/freebsd/),
[VuXML database explanation in the Porter's handbook](https://docs.freebsd.org/en/books/porters-handbook/security/),
[VuXML database as a FreeBSD port](https://www.freshports.org/security/vuxml/),
[pkg-audit(8)](https://man.freebsd.org/cgi/man.cgi?query=pkg-audit),
[vxquery](https://www.freshports.org/security/vxquery/)

## STANDARDS
The **vuxml** utility is not a standard UNIX command.

It tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## PORTABILITY
Tested OK under Windows.

## HISTORY
This implementation was made for the [PNU project](https://github.com/HubTou/PNU).

While working on the [pipinfo(1)](https://github.com/HubTou/pipinfo) tool, I noticed that some Python packages installed as FreeBSD ports
where marked as vulnerable in [Python advisories](https://github.com/pypa/advisory-database) but not in [FreeBSD ports advisories](https://www.vuxml.org/freebsd/index.html).

I made a tool to check the 4000+ FreeBSD ports of Python packages, and found around 1% of them vulnerable.

So I made a library in order to verify if these vulnerable ports where also marked as vulnerable in FreeBSD VuXML,
and got carried away writing this utility to demonstrate the use of the library!

## LICENSE
This utility is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

## CAVEATS
[PORTREVISION and PORTEPOCH](https://people.freebsd.org/~olivierd/porters-handbook/makefile-naming.html) (ie. software versions ending with "\_number" or ",number")
are not taken into account when checking if a vulnerable Python package is also a vulnerable FreeBSD port.
I would have to develop my own versions comparison library in order to handle that (well, maybe one day :-) ).

