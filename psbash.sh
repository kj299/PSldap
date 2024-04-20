#!/bin/bash

# Parameters
LDAP_SERVER=${LDAP_SERVER:-""}
FILTER=${FILTER:-"(uid=$USER)"}
ATTRIBUTES=${ATTRIBUTES:-"displayName telephoneNumber mail"}
USERNAME=${USERNAME:-""}
PASSWORD=${PASSWORD:-""}
SECURE=${SECURE:-false}
BASE_DN=${BASE_DN:-"dc=your-domain,dc=com"}
PAGE_SIZE=${PAGE_SIZE:-100}

# Check if the LDAP server is set
if [ -z "$LDAP_SERVER" ]; then
    echo "Error: No LDAP server specified. Please connect to an LDAP server and try again."
    exit 1
fi

# Set the protocol based on the secure flag
PROTOCOL="ldap"
if [ "$SECURE" = true ] ; then
    PROTOCOL="ldaps"
fi

# Create the LDAP query command
LDAP_QUERY="ldapsearch -x -H $PROTOCOL://$LDAP_SERVER -b $BASE_DN -s sub -z $PAGE_SIZE"

# Add the username and password if provided
if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    LDAP_QUERY="$LDAP_QUERY -D $USERNAME -w $PASSWORD"
fi

# Add the filter and attributes
LDAP_QUERY="$LDAP_QUERY $FILTER $ATTRIBUTES"

# Execute the LDAP query and format the output
eval $LDAP_QUERY | awk -v attributes="$ATTRIBUTES" '
BEGIN {
    split(attributes, attrs, " ");
    for (i in attrs) {
        printf "%-20s", attrs[i];
    }
    printf "\n";
}
/^#/ {next}
{
    for (i in attrs) {
        if ($1 == attrs[i] ":") {
            printf "%-20s", $2;
            delete attrs[i];
        }
    }
    if (length(attrs) == 0) {
        printf "\n";
        split(attributes, attrs, " ");
    }
}'