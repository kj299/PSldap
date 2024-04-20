from ldap3 import Server, Connection, ALL, SUBTREE, NTLM, SIMPLE, SASL
import getpass
import os

# Parameters
ldap_server = None
filter = None
attributes = None
username = None
password = None
secure = False
base_dn = None
delimiter = ","
page_size = 100

# Set the LDAP server and base DN if not provided
if not ldap_server:
    ldap_server = "ldap://your-ldap-server.com"

if not base_dn:
    base_dn = "dc=your-domain,dc=com"

# Set the default filter and attributes if not provided
if not filter:
    filter = "(uid=" + getpass.getuser() + ")"

if not attributes:
    attributes = ["displayName", "telephoneNumber", "mail"]

# Create the LDAP connection and searcher
server = Server(ldap_server, get_info=ALL)
if secure:
    auth = SASL
else:
    auth = SIMPLE

conn = Connection(server, user=username, password=password, authentication=auth, auto_bind=True)

# Perform the search
conn.search(search_base=base_dn, search_filter=filter, search_scope=SUBTREE, attributes=attributes)

# Print the results
for entry in conn.entries:
    print(entry)