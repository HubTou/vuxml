# Ideas for improvement and evolution

## Bugs to be fixed

## Limitations to be removed
* Taking [PORTREVISION and PORTEPOCH](https://people.freebsd.org/~olivierd/porters-handbook/makefile-naming.html) (ie. software versions ending with "\_number" or ",number")
into account when checking if a vulnerable Python package is also a vulnerable FreeBSD port. This would require developping our own versions comparison library.

## New features

## Other possible features
* Disabling color output.
* Ability to use the local database on a FreeBSD with the port collection installed (in /usr/ports/security/vuxml/vuln/). As updating this database requires root privileges, this is not something very interesting. Furthermore the XML dialect used is not readily manageable by Python so the files need a little pre-processing.

