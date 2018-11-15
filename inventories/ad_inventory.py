#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import (division, absolute_import, print_function,
                        unicode_literals)

import os
import sys
import argparse

try:
    import ldap
except ImportError:
    print('Could not import \'ldap\' module.')
    print('Please ensure \'python-ldap\' module is installed.')
    sys.exit(1)

try:
    import json
except ImportError:
    print('Could not import \'json\' module.')
    print('Please ensure \'json\' module is installed.')
    sys.exit(1)

# Configure fallback_args so you don't have to pass any commandline
# arguments in, or alternatively # rely on environmental variables
# (Takes precedence over explicitly defined options),
# eg: user = os.getenv('LDAP_PASS','mypassword123!')

fallback_args = dict(
    ldapuri=os.getenv('AD_URI', 'ldap://ldap.forumsys.com'),
    basedn=os.getenv('AD_BASE', 'DC=example,DC=com'),
    groupname=os.getenv('AD_GROUP', 'Domain Computers'),
    domainname=os.getenv('AD_DOMAIN', 'example.com'),
    user=os.getenv('AD_USER', 'cn=read-only-admin,dc=example,dc=com'),
    password=os.getenv('AD_PASS', 'password'))


class AnsibleInventoryLDAP(object):
    def __init__(self):
        # Create skeleton dict for inventory
        #    '_meta': {
        #        'hostvars': {
        #            'hostA': [ 'hostvarA': 'foo', 'hostvarB': 'bar' ],
        #            'hostB': [ 'hostvarA': 'foo', 'hostvarB': 'bar' ]
        #        }
        #    }
        self.ansible_inventory = {'_meta': {'hostvars': {}}}

        # Parse arguments passed at cli
        self.parse_arguments()

        # Auth against ldap
        self.ldap_auth()

        # Get search results with provided options
        if self.args.os is not False:
            ldapfilter = "(&(objectCategory=Computer)(objectClass=Computer)\
            (operatingSystem=%s))" % (self.args.os)
        else:
            ldapfilter = "(&(objectCategory=Computer)(objectClass=Computer))"

        # Search First Group
        self.ldap_search(ldapfilter)

        # Build JSON
        self.build_hierarchy()

        print(json.dumps(self.ansible_inventory, indent=2))

    def ldap_auth(self):
        """Authenticate to LDAP."""
        try:
            ldapobj = ldap.initialize(self.args.ldapuri)
            ldapobj.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            ldapobj.bind_s(self.args.user, self.args.password)
            self.ldapobj = ldapobj
        except Exception as ex:
            print('Could not successfully authenticate to LDAP.')
            print(ex.__class__.__name__)
            sys.exit(1)

    def ldap_search(self, ldapfilter):
        """Search LDAP in given OU."""
        # Determine the scope value

        scopegroup = ldap.SCOPE_BASE
        scopeall = ldap.SCOPE_SUBTREE
        self.searchresult = []
        # Search ldap for results
        try:
            groupsearch = self.ldapobj.search_s(
                self.args.basedn,
                scopeall,
                filterstr="(&(objectCategory=Group)(objectClass=Group)(CN=%s))"
                % self.args.groupname,
            )
            self.groupname = (groupsearch[0][0])
            if self.groupname is not None:
                groupsearch = self.ldapobj.search_s(self.groupname, scopegroup)
                for member in groupsearch:
                    member = member[-1].get('member')
                    if member is not None:
                        for item in member:
                            computer = item.decode("utf-8")
                            self.searchresult = self.searchresult + (
                                self.ldapobj.search_s(computer, scopegroup,
                                                      ldapfilter))
                    else:
                        self.searchresult = []
            else:
                print('Error Group not Found', file=sys.stderr)
                sys.exit(1)

        except ldap.REFERRAL:
            print(
                "Error: LDAP referral received. Is the Group Name correct?",
                file=sys.stderr)
            sys.exit(1)
        except ldap.INVALID_CREDENTIALS:
            print("Error: Invalid credentials", file=sys.stderr)
            sys.exit(1)
        except Exception as ex:
            print(ex.__class__.__name__)
        finally:
            self.ldapobj.unbind_s()

    def add_inventory_entry(self, host=None, group_name=None, hostvars=None):
        # Example output:
        # {
        #    'groupnameA': {
        #        'hosts': [ 'hostA', 'hostB', 'hostC' ],
        #        'vars': { 'groupvarA': 'foo', 'groupvarB': 'bar' },
        #     },
        #    '_meta': {
        #        'hostvars': {
        #            'hostA': [ 'hostvarA': 'foo', 'hostvarB': 'bar' ],
        #            'hostB': [ 'hostvarA': 'foo', 'hostvarB': 'bar' ]
        #        }
        #    }
        # }

        # Force the group name to lowercase
        group_name = group_name.lower()

        # Append the --group-prefix value if one is specified
        if self.args.group_prefix is not False:
            group_name = self.args.group_prefix + group_name

        # If the group doesn't exist, then create it
        if group_name not in list(self.ansible_inventory.keys()):
            self.ansible_inventory[group_name] = {
                'hosts': [],
                'vars': {},
            }

        # Add the host if a host was passed
        if host is not None:
            # The host should never get added twice anyway, but we'll
            # add this as a safeguard

            if host not in self.ansible_inventory[group_name]['hosts']:
                self.ansible_inventory[group_name]['hosts'].append(host)

            # And add the hostvars for the host to the _meta dict
            if hostvars is not None:
                self.ansible_inventory['_meta']['hostvars'][host] = hostvars

    def build_hierarchy(self):
        searchresult = self.searchresult
        try:
            basedn = self.groupname
            groupname = basedn.replace(' ', '_').replace('CN=', '').replace(
                'OU=', '').replace('DC=', '').split(',')[0]
        except Exception:
            pass

        for dn, attrs in searchresult:
            # Collect information about the host
            hostvars = {}

            try:
                hostvars['name'] = attrs['dNSHostName'][0].decode("utf-8")
            except Exception:
                name = dn.replace(' ', '_').replace('CN=', '').replace(
                    'OU=', '').replace('DC=', '').split(',')[0].lower()
                hostvars['name'] = ("%s.%s") % (name, self.args.domainname)

            hostvars['cn'] = attrs['cn'][0].decode("utf-8")
            hostvars['dn'] = attrs['distinguishedName'][0].decode("utf-8")

            try:
                hostvars['osname'] = attrs['operatingSystem'][0].decode(
                    "utf-8")
                if hostvars['osname'] is not None and "windows" in hostvars[
                        'osname'].lower():
                    hostvars['ansible_port'] = 5985
                    hostvars['ansible_connection'] = 'winrm'
                    hostvars['ansible_winrm_transport'] = 'kerberos'
                    hostvars['ansible_winrm_server_cert_validation'] = 'ignore'
                    hostvars['ansible_winrm_operation_timeout_sec'] = 200
                    hostvars['ansible_winrm_read_timeout_sec'] = 600
            except Exception:
                pass

            try:
                hostvars['osversion'] = attrs['operatingSystemVersion'][
                    0].decode("utf-8")
            except Exception:
                pass

            # Do we want fqdn or just the basic hostname
            if self.args.fqdn is True:
                hostvars['inventory_name'] = hostvars['name']
            else:
                hostvars['inventory_name'] = hostvars['cn']

            self.add_inventory_entry(
                group_name=groupname,
                host=hostvars['inventory_name'],
                hostvars=hostvars)

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='Populate ansible inventory from LDAP.')
        parser.add_argument(
            '--groupname',
            help='Group Name to search in.',
            default=fallback_args['groupname']),
        parser.add_argument(
            '--basedn',
            '-b',
            help='DN of the OU to search in.',
            default=fallback_args['basedn'])
        parser.add_argument(
            '--user',
            '-u',
            help='DN of user to authenticate as.',
            default=fallback_args['user'])
        parser.add_argument(
            '--password',
            '-p',
            help='Password of user to authenticate as.',
            default=fallback_args['password'])
        parser.add_argument(
            '--ldapuri',
            help='URI of the LDAP server (ldap://domain.local).',
            default=fallback_args['ldapuri'])
        parser.add_argument(
            '--domainname',
            help='Name of the Domain (domain.local). This name will be\
            attached to computers without dNSHostName Attribute.',
            default=fallback_args['domainname'])
        parser.add_argument(
            '--fqdn',
            help='Output the hosts FQDN, not just host name',
            default=True,
            action='store_true')
        parser.add_argument(
            '--os',
            '-os',
            help='Only return hosts matching the OS specified (Uses ldap\
             formatting, so \'*windows*\').',
            default=False)
        parser.add_argument(
            '--group-prefix', help='Prefix all group names.', default=False)

        args_hostlist = parser.add_mutually_exclusive_group()
        args_hostlist.add_argument(
            '--list',
            help='List all nodes from specified Security Group',
            action='store_true')
        args_hostlist.add_argument('--host', help='Not implemented.')

        self.args = parser.parse_args()


def main():
    # Instantiate the inventory object
    AnsibleInventoryLDAP()


if __name__ == '__main__':
    main()
