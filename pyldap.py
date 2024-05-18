import argparse
import sys
from ldap3 import Server, Connection, ALL
import os
import getpass

def get_existing_connection():
    # Check if environment variables indicate an existing connection
    if os.getenv("LDAP_CONNECTED") == "true":
        server_address = os.getenv("LDAP_SERVER")
        user_dn = os.getenv("LDAP_USER")
        password = os.getenv("LDAP_PASSWORD")
        return connect_to_ldap(server_address, user_dn, password)
    return None

def connect_to_ldap(server_address, user_dn=None, password=None):
    server = Server(server_address, get_info=ALL)
    conn = None
    if user_dn and password:
        conn = Connection(server, user=user_dn, password=password)
        if not conn.bind():
            raise Exception("Failed to bind to LDAP server with provided credentials")
    else:
        conn = Connection(server)
        if not conn.bind():
            raise Exception("Failed to bind to LDAP server anonymously")
    return conn

def prompt_for_credentials():
    user_dn = input("Enter User DN: ")
    password = getpass.getpass("Enter Password: ")
    return user_dn, password

def search_ldap(conn, base_dn, search_filter, attributes):
    conn.search(base_dn, search_filter, attributes=attributes)
    return conn.entries

def format_output(entries, delimiter, combine_same_attributes):
    if combine_same_attributes:
        for entry in entries:
            output = []
            for attr in entry.entry_attributes:
                values = ";".join(entry[attr]) if len(entry[attr]) > 1 else entry[attr][0]
                output.append(f"{attr}{delimiter}{values}")
            print(delimiter.join(output))
    else:
        for entry in entries:
            output = []
            for attr in entry.entry_attributes:
                for value in entry[attr]:
                    output.append(f"{attr}{delimiter}{value}")
            print(delimiter.join(output))

def display_help():
    help_text = """
Usage: ldap_query.py -s <server> -b <base_dn> -f <filter> -a <attributes> [-u <user_dn>] [-p <password>] [-d <delimiter>] [-c]
Query LDAP server similar to ldapsearch.

Options:
  -s, --server      LDAP server address (required if no existing connection)
  -u, --user        User DN for LDAP authentication
  -p, --password    Password for LDAP authentication
  -b, --base        Base DN for LDAP search (required)
  -f, --filter      Search filter (required)
  -a, --attributes  Attributes to retrieve (required)
  -d, --delimiter   Delimiter for output (default is carriage return and line feed)
  -c, --combine     Combine attributes with same name into single column

Example:
  python ldap_query.py -s ldap://your-ldap-server -b "dc=example,dc=com" -f "(objectClass=*)" -a cn sn mail -d "," -c
"""
    print(help_text)

def main():
    parser = argparse.ArgumentParser(description="Query LDAP server similar to ldapsearch.", add_help=False)
    parser.add_argument("-s", "--server", help="LDAP server address (required if no existing connection)")
    parser.add_argument("-u", "--user", help="User DN for LDAP authentication")
    parser.add_argument("-p", "--password", help="Password for LDAP authentication")
    parser.add_argument("-b", "--base", required=True, help="Base DN for LDAP search")
    parser.add_argument("-f", "--filter", required=True, help="Search filter")
    parser.add_argument("-a", "--attributes", nargs="+", required=True, help="Attributes to retrieve")
    parser.add_argument("-d", "--delimiter", default="\r\n", help="Delimiter for output (default is carriage return and line feed)")
    parser.add_argument("-c", "--combine", action="store_true", help="Combine attributes with same name into single column")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    args = parser.parse_args()

    if args.help or len(sys.argv) == 1:
        display_help()
        sys.exit(0)

    try:
        conn = get_existing_connection()
        if conn is None:
            if args.server is None:
                raise Exception("No existing connection found and no server specified.")
            user_dn = args.user
            password = args.password
            if not user_dn or not password:
                user_dn, password = prompt_for_credentials()
            conn = connect_to_ldap(args.server, user_dn, password)
        entries = search_ldap(conn, args.base, args.filter, args.attributes)
        format_output(entries, args.delimiter, args.combine)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
