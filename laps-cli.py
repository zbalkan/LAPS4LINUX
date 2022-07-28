#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from os import path, makedirs, rename
from datetime import datetime
from dns import resolver, rdatatype
import ldap3
from ldap3.utils.conv import escape_filter_chars
import getpass
import argparse
import json
import sys
import os
from configuration import CfgServer, ClientConfig
import helpers
import logging
import logging.handlers


class LapsCli():
    PLATFORM = sys.platform.lower()

    PRODUCT_NAME: str = 'LAPS4LINUX CLI'
    PRODUCT_VERSION: str = '1.5.3'
    PRODUCT_WEBSITE: str = 'https://github.com/schorschii/laps4linux'

    logger: logging.Logger  # no default value

    useKerberos: bool = True
    gcModeOn: bool = False
    server: ldap3.ServerPool  # no default value
    connection: ldap3.Connection  # no default value
    tmpDn: str = ''

    cfgPresetDirWindows: str = sys.path[0]
    cfgPresetDirUnix: str = '/etc'
    cfgPresetFile: str = 'laps-client.json'
    cfgPresetPath: str = (cfgPresetDirWindows if sys.platform.lower()
                          == 'win32' else cfgPresetDirUnix) + '/' + cfgPresetFile

    cfgDir: str = str(Path.home()) + '/.config/laps-client'
    cfgPath: str = cfgDir + '/settings.json'
    cfgPathOld: str = str(Path.home()) + '/.laps-client.json'
    cfg: ClientConfig  # no default value

    def __init__(self, useKerberos: bool) -> None:
        self.initLogger()
        self.LoadSettings()
        self.useKerberos = useKerberos

        # show version information
        print(self.PRODUCT_NAME + ' v' + self.PRODUCT_VERSION)
        print(self.PRODUCT_WEBSITE)

    def initLogger(self) -> None:
        self.logger = logging.getLogger(self.PRODUCT_NAME)
        self.logger.setLevel(logging.DEBUG)
        if(self.PLATFORM == 'win32'):
            self.logger.addHandler(
                logging.handlers.TimedRotatingFileHandler(
                    path='./laps-gui.log', when='m', interval=1, backupCount=5))
        else: # any *NIX variant
            self.logger.addHandler(
                logging.handlers.SysLogHandler(address='/dev/log'))
        excepthook = self.logger.error

    def LoadSettings(self) -> None:
        if(not path.isdir(self.cfgDir)):
            makedirs(self.cfgDir, exist_ok=True)
        # protect temporary .remmina file by limiting access to our config folder
        if(self.PLATFORM == 'linux'):
            os.chmod(self.cfgDir, 0o700)
        if(path.exists(self.cfgPathOld)):
            rename(self.cfgPathOld, self.cfgPath)

        if(path.isfile(self.cfgPath)):
            cfgPath = self.cfgPath
        elif(path.isfile(self.cfgPresetPath)):
            cfgPath = self.cfgPresetPath
        else:
            raise Exception("Could not find the settings file.")

        try:
            with open(cfgPath) as f:
                cfgJson = json.load(f)
                self.cfg = ClientConfig.from_dict(cfgJson)
        except Exception as e:
            print('Error loading settings file: ' + str(e))

    def SaveSettings(self) -> None:
        try:
            with open(self.cfgPath, 'w') as json_file:
                json.dump({
                    'server': self.cfg.server,
                    'domain': self.cfg.domain,
                    'username': self.cfg.username,
                    'ldap-attribute-password': self.cfg.ldap_attribute_password,
                    'ldap-attribute-password-expiry': self.cfg.ldap_attribute_password_expiry,
                    'ldap-attributes': self.cfg.ldap_attributes
                }, json_file, indent=4)
        except Exception as e:
            print('Error saving settings file: ' + str(e))

    def SearchComputer(self, computerName: str) -> None:
        # check and escape input
        if computerName.strip() == '':
            return
        if not computerName == '*':
            computerName = escape_filter_chars(computerName)

        # ask for credentials and print connection details
        print('')
        if not self.checkCredentialsAndConnect():
            return
        self.printResult('Connection', str(
            self.connection.server) + ' ' + self.cfg.username + '@' + self.cfg.domain)

        try:
            # compile query attributes
            attributes = ['SAMAccountname', 'distinguishedName']
            attrs = self.cfg.ldap_attributes.to_dict()
            for key in attrs:
                title = key  # unused
                attribute = attrs[key]
                attributes.append(attribute)

            # start LDAP search
            count = 0
            self.connection.search(
                search_base=self.createLdapBase(self.cfg.domain),
                search_filter='(&(objectCategory=computer)(name=' +
                computerName + '))',
                attributes=attributes
            )
            for entry in self.connection.entries:
                count += 1
                # display result list
                if computerName == '*':
                    displayValues: list[str] = []
                    attrs = self.cfg.ldap_attributes.to_dict()
                    for key in attrs:
                        title = key  # unused
                        attribute = attrs[key]
                        displayValues.append(
                            str(entry[attribute]).ljust(25))
                    print(str(entry['SAMAccountname']) +
                          ' : ' + str.join(' : ', displayValues))
                # display single result
                else:
                    self.printResult('Found', str(entry['distinguishedName']))
                    self.tmpDn = str(entry['distinguishedName'])
                    self.queryAttributes()
                    return

            # no result found
            if count == 0:
                self.printResult('No Result For', computerName)
        except Exception as e:
            # display error
            self.printResult('Error', str(e))
            print(str(e))
            # reset connection
            self.server = None
            self.connection = None

        self.tmpDn = ''

    def SetExpiry(self, newExpirationDateTimeString: str) -> None:
        # check if dn of target computer object is known
        if self.tmpDn.strip() == '':
            return

        try:
            # calc new time
            newExpirationDate = datetime.strptime(
                newExpirationDateTimeString, '%Y-%m-%d %H:%M:%S')
            newExpirationDateTime = helpers.dt_to_filetime(newExpirationDate)
            self.printResult('New Expiration', str(
                newExpirationDateTime) + ' (' + str(newExpirationDate) + ')')

            # start LDAP modify
            self.connection.modify(self.tmpDn, {self.cfg.ldap_attribute_password_expiry: [
                                   (ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])]})
            if self.connection.result['result'] == 0:
                print('Expiration Date Changed Successfully.')
            else:
                print('Unable to change expiration date. ' +
                      str(self.connection.result['message']))

        except Exception as e:
            # display error
            self.printResult('Error', str(e))
            # reset connection
            self.server = None
            self.connection = None

    def queryAttributes(self) -> None:
        if(not self.reconnectForAttributeQuery()):
            return

        # compile query attributes
        attributes = ['SAMAccountname', 'distinguishedName']
        attrs = self.cfg.ldap_attributes.to_dict()
        for key in attrs:
            title = key
            attribute = attrs[key]
            attributes.append(attribute)

        # start LDAP search
        self.connection.search(
            search_base=self.tmpDn,
            search_filter='(objectCategory=computer)',
            attributes=attributes
        )
        for entry in self.connection.entries:
            # display single result
            for key in attrs:
                title = key
                attribute = attrs[key]
                if(attribute == self.cfg.ldap_attribute_password_expiry):
                    try:
                        self.printResult(title, str(entry[attribute]) + ' (' + str(
                            helpers.filetime_to_dt(int(str(entry[attribute])))) + ')')
                    except Exception as e:
                        self.printResult('Error', str(e))
                        self.printResult(
                            title, str(entry[attribute]))
                else:
                    self.printResult(title, str(entry[attribute]))
            return

    def printResult(self, attribute: str, value: str) -> None:
        print((attribute + ':').ljust(26) + value)

    def checkCredentialsAndConnect(self) -> bool:
        # ask for server address and domain name if not already set via config file
        if self.cfg.domain == "":
            item = input('♕ Domain Name (e.g. example.com): ')
            if item and item.strip() != "":
                self.cfg.domain = item
                self.server = None
            else:
                return False
        if len(self.cfg.server) == 0:
            # query domain controllers by dns lookup
            try:
                res = resolver.query(
                    qname=f"_ldap._tcp.{self.cfg.domain}", rdtype=rdatatype.SRV, lifetime=10)
                for srv in res.rrset:
                    serverEntry = CfgServer(
                        str(srv.target), srv.port, (srv.port == 636))
                    print('DNS auto discovery found server: ' +
                          json.dumps(serverEntry))
                    self.cfg.server.append(serverEntry)
            except Exception as e:
                print('DNS auto discovery failed: ' + str(e))
            # ask user to enter server names if auto discovery was not successful
            if len(self.cfg.server) == 0:
                item = input('💻 LDAP Server Address: ')
                if item and item.strip() != "":
                    self.cfg.server.append(CfgServer(item, 389, False))
                    self.server = None
        self.SaveSettings()

        # establish server connection
        if self.server == None:
            try:
                serverArray: list[ldap3.Server] = []
                for server in self.cfg.server:
                    if(server.gc_port):
                        port = server.gc_port
                        self.gcModeOn = True
                    else:
                        port = server.port

                    serverArray.append(ldap3.Server(
                        server.address, port=port, use_ssl=server.ssl, get_info='ALL'))
                self.server = ldap3.ServerPool(
                    serverArray, ldap3.ROUND_ROBIN, active=True, exhaust=True)
            except Exception as e:
                print('Error connecting to LDAP server: ', str(e))
                return False

        # try to bind to server via Kerberos
        try:
            if(self.useKerberos):
                self.connection = ldap3.Connection(
                    self.server,
                    authentication=ldap3.SASL,
                    sasl_mechanism=ldap3.KERBEROS,
                    auto_referrals=True,
                    auto_bind='DEFAULT'
                )
                # self.connection.bind()
                return True  # return if connection created successfully
        except Exception as e:
            print('Unable to connect via Kerberos: ' + str(e))

        # ask for username and password for NTLM bind
        if self.cfg.username == "":
            item = input(
                '👤 Username [' + getpass.getuser() + ']: ') or getpass.getuser()
            if item and item.strip() != "":
                self.cfg.username = item
                self.connection = None
            else:
                return False
        if self.cfg.ldap_attribute_password == "":
            item = getpass.getpass(
                '🔑 Password for »' + self.cfg.username + '«: ')
            if item and item.strip() != "":
                self.cfg.ldap_attribute_password = item
                self.connection = None
            else:
                return False
        self.SaveSettings()

        # try to bind to server with username and password
        try:
            self.connection = ldap3.Connection(
                self.server,
                user=self.cfg.username + '@' + self.cfg.domain,
                password=self.cfg.ldap_attribute_password,
                authentication=ldap3.SIMPLE,
                auto_referrals=True,
                auto_bind='DEFAULT'
            )
            # self.connection.bind()
            print('')  # separate user input from results by newline
        except Exception as e:
            self.cfg.username = ''
            self.cfg.ldap_attribute_password = ''
            print('Error binding to LDAP server: ', str(e))
            return False

        return True

    def reconnectForAttributeQuery(self) -> bool:
        # global catalog was not used for search - we can use the same connection for attribute query
        if(not self.gcModeOn):
            return True
        # global catalog was used for search (this buddy is read only and not all attributes are replicated into it)
        # -> that's why we need to establish a new connection to the "normal" LDAP port
        # LDAP referrals to the correct (sub)domain controller is handled automatically by ldap3
        serverArray: list[ldap3.Server] = []
        for server in self.cfg.server:
            serverArray.append(ldap3.Server(
                server.address, port=server.port, use_ssl=server.ssl, get_info='ALL'))
        server = ldap3.ServerPool(
            serverArray, ldap3.ROUND_ROBIN, active=True, exhaust=True)
        # try to bind to server via Kerberos
        try:
            if(self.useKerberos):
                self.connection = ldap3.Connection(server,
                                                   authentication=ldap3.SASL,
                                                   sasl_mechanism=ldap3.KERBEROS,
                                                   auto_referrals=True,
                                                   auto_bind='DEFAULT'
                                                   )
                return True
        except Exception as e:
            print('Unable to connect via Kerberos: ' + str(e))
        # try to bind to server with username and password
        try:
            self.connection = ldap3.Connection(server,
                                               user=self.cfg.username + '@' + self.cfg.domain,
                                               password=self.cfg.ldap_attribute_password,
                                               authentication=ldap3.SIMPLE,
                                               auto_referrals=True,
                                               auto_bind='DEFAULT'
                                               )
            return True
        except Exception as e:
            print('Error binding to LDAP server: ' + str(e))
            return False

    def createLdapBase(self, domain: str) -> str:
        # convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
        search_base: str = ""
        base = domain.split(".")
        for b in base:
            search_base += "DC=" + b + ","
        return search_base[:-1]


def main() -> None:
    parser = argparse.ArgumentParser(
        epilog='© 2021-2022 Georg Sieber - https://georg-sieber.de')
    parser.add_argument('search', default=None, nargs='*', metavar='COMPUTERNAME',
                        help='Search for this computer(s) and display the admin password. Use "*" to display all computer passwords found in LDAP directory. If you omit this parameter, the interactive shell will be started, which allows you to do multiple queries in one session.')
    parser.add_argument('-e', '--set-expiry', default=None, metavar='"2020-01-01 00:00:00"',
                        help='Set new expiration date for computer found by search string.')
    parser.add_argument('-K', '--no-kerberos', action='store_true',
                        help='Do not use Kerberos authentication if available, ask for LDAP simple bind credentials.')
    parser.add_argument('--version', action='store_true',
                        help='Print version and exit.')
    args = parser.parse_args()

    cli = LapsCli(not args.no_kerberos)

    if(args.version):
        return

    # do LDAP search by command line arguments
    if(args.search):
        validSearches = 0
        for term in args.search:
            if(term.strip() == '*'):
                cli.SearchComputer('*')
                return

            if(term.strip() != ''):
                validSearches += 1
                cli.SearchComputer(term.strip())
                if(args.set_expiry and args.set_expiry.strip() != ''):
                    cli.SetExpiry(args.set_expiry.strip())

        # if at least one computername was given, we do not start the interactive shell
        if(validSearches > 0):
            return

    # do LDAP search by interactive shell input
    print('')
    print('Welcome to interactive shell. Please enter a computer name to search for.')
    print('Parameter --help provides more information.')
    while 1:
        # get keyboard input
        cmd = input('>> ')
        if(cmd == 'exit' or cmd == 'quit'):
            return
        else:
            cli.SearchComputer(cmd.strip())


if __name__ == '__main__':
    main()
