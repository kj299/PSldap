# PSldap
Powershell Script to query current AD via ldap filter
This script imports the ActiveDirectory module and gets the current domain name. It then sets a default LDAP filter of (objectClass=user) and prompts the user to customize it. If the user enters a custom filter, it uses that instead of the default.

The script then builds a search query using the domain name and LDAP filter, executes the query, and displays the results.
