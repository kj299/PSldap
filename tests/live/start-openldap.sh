#!/usr/bin/env bash
# Starts a throwaway OpenLDAP server for the live test tier.
#
#   tests/live/start-openldap.sh <work-dir> [port]
#
# Requires slapd (apt-get install slapd ldap-utils). Listens on
# ldap://127.0.0.1:<port> (default 3389) with suffix dc=example,dc=com,
# loads fixture.ldif, and enables server-side sorting (sssvlv).
# Bind as cn=admin,dc=example,dc=com / password (unlimited), or
# cn=read-only-admin,dc=example,dc=com / password (server size limit 5,
# to exercise server-enforced limits).
set -euo pipefail

work="${1:?usage: start-openldap.sh <work-dir> [port]}"
port="${2:-3389}"
here="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$work/db"
work="$(cd "$work" && pwd)"

cat > "$work/slapd.conf" <<CONF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
modulepath /usr/lib/ldap
moduleload back_mdb
moduleload sssvlv
pidfile $work/slapd.pid
database mdb
maxsize 104857600
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw password
directory $work/db
access to attrs=userPassword by self write by anonymous auth by * none
access to * by * read
limits dn.exact="cn=read-only-admin,dc=example,dc=com" size=5
overlay sssvlv
CONF

slapadd -f "$work/slapd.conf" -l "$here/fixture.ldif"
slapd -f "$work/slapd.conf" -h "ldap://127.0.0.1:$port/"

# Wait until it answers.
for _ in $(seq 1 20); do
    if ldapsearch -x -H "ldap://127.0.0.1:$port" -b dc=example,dc=com -s base '(objectClass=*)' dn >/dev/null 2>&1; then
        echo "OpenLDAP test server ready on ldap://127.0.0.1:$port"
        exit 0
    fi
    sleep 0.5
done
echo "OpenLDAP test server did not start" >&2
exit 1
