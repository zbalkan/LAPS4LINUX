#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import path
from datetime import datetime, timedelta
from dns import resolver, rdatatype
from Crypto.Hash import SHA512
import ldap3
import subprocess
import secrets
import socket
import argparse
import json
import os
import logging
import logging.handlers
import traceback
import helpers as helpers
from configuration import Configuration


class LapsRunner():
    PRODUCT_NAME: str = 'LAPS4LINUX Runner'
    PRODUCT_VERSION: str = '1.5.2'
    PRODUCT_WEBSITE: str = 'https://github.com/schorschii/laps4linux'

    server: ldap3.ServerPool  # no default value
    connection: ldap3.Connection  # no default value
    logger: logging.Logger  # no default value

    cfgPath: str = '/etc/laps-runner.json'
    cfg: Configuration

    tmpDn: str = ''
    tmpPassword: str = ''
    tmpExpiry: str = ''
    tmpExpiryDate: datetime  # no default value

    def __init__(self, *args, **kwargs) -> None:
        # init logger
        self.logger = logging.getLogger('LAPS4LINUX')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(
            logging.handlers.SysLogHandler(address='/dev/log'))

        # show note
        print(self.PRODUCT_NAME + ' v' + self.PRODUCT_VERSION)
        if not 'slub' in self.cfg.domain:
            print('If you like LAPS4LINUX please consider making a donation to support further development (' + self.PRODUCT_WEBSITE + ').')
        else:
            print(self.PRODUCT_WEBSITE)
        print('')

    def getHostname(self) -> str:
        if(self.cfg.hostname.strip() == ''):
            return socket.gethostname().upper()
        else:
            return self.cfg.hostname.strip().upper()

    def initKerberos(self) -> None:
        # query new kerberos ticket
        cmd: list[str] = ['kinit', '-k', '-c', self.cfg.cred_cache_file,
                          self.getHostname() + '$']
        res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
        if res.returncode != 0:
            raise Exception(
                ' '.join(cmd) + ' returned non-zero exit code ' + str(res.returncode))

    def connectToServer(self) -> None:
        # set environment variables for kerberos operations
        os.environ['KRB5CCNAME'] = self.cfg.cred_cache_file
        os.environ['KRB5_CLIENT_KTNAME'] = self.cfg.client_keytab_file

        # connect to server with kerberos ticket
        serverArray: list[ldap3.Server] = []
        if(len(self.cfg.server) == 0):
            # query domain controllers by dns lookup
            res = resolver.query(
                qname=f"_ldap._tcp.{self.cfg.domain}", rdtype=rdatatype.SRV, lifetime=10)
            for srv in res.rrset:
                serverArray.append(ldap3.Server(
                    host=str(srv.target), port=636, use_ssl=True, get_info=ldap3.ALL))
        else:
            # use servers given in config file
            for server in self.cfg.server:
                serverArray.append(ldap3.Server(
                    server.address, port=server.port, use_ssl=server.ssl, get_info=ldap3.ALL))
        self.server = ldap3.ServerPool(
            serverArray, ldap3.ROUND_ROBIN, active=True, exhaust=True)

        try:
            self.connection = ldap3.Connection(
                self.server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, auto_bind='DEFAULT')

            print('Connected as: ' + str(self.connection.server) + ' ' +
                  self.connection.extend.standard.who_am_i() + '@' + self.cfg.domain)
        except Exception as e:
            print("No connection established")
            self.logger.exception(e)

    def searchComputer(self) -> bool:
        # check and escape input
        computerName: str = ldap3.utils.conv.escape_filter_chars(
            self.getHostname())

        # start query
        self.connection.search(
            search_base=self.createLdapBase(self.cfg.domain),
            search_filter='(&(objectCategory=computer)(name=' +
            computerName + '))',
            attributes=[self.cfg.ldap_attribute_password,
                        self.cfg.ldap_attribute_password_expiry, 'SAMAccountname', 'distinguishedName']
        )
        for entry in self.connection.entries:
            # display result
            self.tmpDn = str(entry['distinguishedName'])
            self.tmpPassword = self.cfg.ldap_attribute_password
            self.tmpExpiry = self.cfg.ldap_attribute_password_expiry
            try:
                # date conversion will fail if there is no previous expiration time saved
                self.tmpExpiryDate = helpers.filetime_to_dt(
                    int(self.cfg.ldap_attribute_password_expiry))
            except Exception as e:
                print('Unable to parse date ' + self.cfg.ldap_attribute_password_expiry +
                      ' - assuming that no expiration date is set.')
                self.tmpExpiryDate = datetime.utcfromtimestamp(0)
            return True

        # no result found
        print('No Result For: ' + computerName)

        self.tmpDn = ''
        self.tmpPassword = ''
        self.tmpExpiry = ''
        # self.tmpExpiryDate
        return False

    def updatePassword(self) -> None:
        # generate new values
        newPassword = self.generatePassword()
        newPasswordHashed = SHA512.new(bytes(newPassword, 'utf-8'))
        newExpirationDate = datetime.now(
        ) + timedelta(days=self.cfg.password_days_valid)

        # update in directory
        self.setPasswordAndExpiry(newPassword, newExpirationDate)

        # update password in local database
        cmd: list[str] = ['usermod', '-p',
                          newPasswordHashed.digest().decode('utf-8'), self.cfg.password_change_user]
        res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, universal_newlines=True)
        if res.returncode == 0:
            print('Password successfully changed in local database.')
            self.logger.debug(self.PRODUCT_NAME + ': Changed password of user ' +
                              self.cfg.password_change_user + ' in local database.')
        else:
            raise Exception(
                ' '.join(cmd) + ' returned non-zero exit code ' + str(res.returncode))

    def setPasswordAndExpiry(self, newPassword: str, newExpirationDate: datetime) -> None:
        # check if dn of target computer object is known
        if self.tmpDn.strip() == '':
            return

        # calc new time
        newExpirationDateTime = helpers.dt_to_filetime(newExpirationDate)

        # start query
        self.connection.modify(self.tmpDn, {
            self.cfg.ldap_attribute_password_expiry: [(ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])],
            self.cfg.ldap_attribute_password: [(ldap3.MODIFY_REPLACE, newPassword)],
        })
        if self.connection.result['result'] == 0:
            print('Password and expiration date changed successfully in LDAP directory (new expiration ' +
                  str(newExpirationDate) + ').')
        else:
            raise Exception('Could not update password in LDAP directory.')

    def generatePassword(self) -> str:
        return ''.join(secrets.choice(self.cfg.password_alphabet) for i in range(len(self.cfg.password_alphabet)))

    def createLdapBase(self, domain: str) -> str:
        search_base: str = ""
        base = domain.split(".")
        for b in base:
            search_base += "DC=" + b + ","
        return search_base[:-1]

    def LoadSettings(self) -> None:
        if(not path.isfile(self.cfgPath)):
            raise Exception('Config file not found: ' + self.cfgPath)
        with open(self.cfgPath) as f:
            jsonstring = json.load(f)
            try:
                self.cfg = Configuration.from_dict(jsonstring)
            except:
                print('Could not read the configuration file. Please check the values.')


def main() -> None:
    runner = LapsRunner()

    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--force', action='store_true',
                        help='Force updating password, even if it is not expired')
    parser.add_argument('-c', '--config', default=runner.cfgPath,
                        help='Path to config file [' + str(runner.cfgPath) + ']')
    args = parser.parse_args()
    if args.config:
        runner.cfgPath = args.config

    # start workflow
    try:
        runner.LoadSettings()
        runner.initKerberos()
        runner.connectToServer()
        runner.searchComputer()

        if runner.tmpExpiryDate < datetime.now():
            print('Updating password (expired ' + str(runner.tmpExpiryDate) + ')')
            runner.updatePassword()
        elif args.force:
            print('Updating password (forced update)...')
            runner.updatePassword()
        else:
            print('Password will expire in ' +
                  str(runner.tmpExpiryDate) + ', no need to update.')

    except Exception as e:
        print(traceback.format_exc())
        runner.logger.critical(runner.PRODUCT_NAME +
                               ': Error while executing workflow: ' + str(e))
        exit(1)

    return


if __name__ == '__main__':
    main()
