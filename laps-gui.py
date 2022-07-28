#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import getpass
import json
import logging
import logging.handlers
import os
import sys
import typing
from datetime import datetime
from os import makedirs, path, rename
from pathlib import Path
from shutil import which
from typing import Literal, NoReturn
from urllib.parse import unquote

import ldap3
from dns import rdatatype, resolver, rrset
from ldap3.utils.conv import escape_filter_chars
from PyQt5 import Qt
from PyQt5.QtGui import QFont, QFontDatabase, QIcon
from PyQt5.QtWidgets import (QAction, QApplication, QCalendarWidget, QDialog,
                             QDialogButtonBox, QGridLayout, QInputDialog, QLabel, QLineEdit,
                             QMainWindow, QMessageBox, QPushButton, QVBoxLayout, QWidget)

import helpers
from configuration import CfgServer, ClientConfig
from freerdpconnector import FreeRDPConnector
from remminaconnector import RemminaConnector
from sshconnector import SshConnector


class LapsMainWindow(QMainWindow):
    PLATFORM = sys.platform.lower()

    PRODUCT_NAME: str = 'LAPS4WINDOWS' if PLATFORM == 'win32' else 'LAPS4MAC' if PLATFORM == 'darwin' else 'LAPS4LINUX'
    PRODUCT_VERSION: str = '1.5.3'
    PRODUCT_WEBSITE: str = 'https://github.com/schorschii/laps4linux'
    PROTOCOL_SCHEME: str = 'laps://'
    PRODUCT_ICON: str = 'laps.png'
    PRODUCT_ICON_PATH: str = '/usr/share/pixmaps'

    logger: logging.Logger  # no default value

    useKerberos: bool = True
    gcModeOn: bool = False
    server: ldap3.ServerPool  # no default value
    connection: ldap3.Connection  # no default value
    tmpDn: str = ''

    cfgPresetDirWindows: str = path.dirname(sys.executable) if getattr(
        sys, 'frozen', False) else sys.path[0]
    cfgPresetDirUnix: str = '/etc'
    cfgPresetFile: str = 'laps-client.json'
    cfgPresetPath: str = (cfgPresetDirWindows if PLATFORM ==
                          'win32' else cfgPresetDirUnix) + '/' + cfgPresetFile

    cfgDir: str = str(Path.home()) + '/.config/laps-client'
    cfgPath: str = cfgDir + '/settings.json'
    cfgPathOld: str = str(Path.home()) + '/.laps-client.json'
    cfg: ClientConfig  # no default value
    refLdapAttributesTextBoxes: dict[str, QLineEdit] = {}

    cfgPathRemmina: str = cfgDir + '/laps.remmina'
    useRemmina: bool = False
    useFreeRdp: bool = False
    useSsh: bool = False
    renderConnectMenu: bool = False

    def __init__(self) -> None:
        super(LapsMainWindow, self).__init__()
        self.initLogger()
        self.LoadSettings()
        self.InitUI()

    def initLogger(self) -> None:
        self.logger = logging.getLogger(self.PRODUCT_NAME)
        self.logger.setLevel(logging.DEBUG)
        if(self.PLATFORM == 'win32'):
            self.logger.addHandler(
                logging.handlers.TimedRotatingFileHandler(
                    filename='laps-gui.log', when='m', interval=1, backupCount=5))
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
            self.showErrorDialog('Error loading settings file', str(e))

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
            self.showErrorDialog('Error saving settings file', str(e))

    def InitUI(self) -> None:
        # Icon Selection
        if(getattr(sys, 'frozen', False)):
            # included via pyinstaller (Windows & macOS)
            self.PRODUCT_ICON_PATH = sys._MEIPASS
        self.iconPath = path.join(self.PRODUCT_ICON_PATH, self.PRODUCT_ICON)
        if(path.exists(self.iconPath)):
            self.icon = QIcon(self.iconPath)
            self.setWindowIcon(self.icon)

        # Menubar
        mainMenu = self.menuBar()

        # File Menu
        fileMenu = mainMenu.addMenu('&File')

        searchAction = QAction('&Search', self)
        searchAction.setShortcut('F2')
        searchAction.triggered.connect(self.OnClickSearch)
        fileMenu.addAction(searchAction)
        if(self.cfg.ldap_attribute_password_expiry.strip() != ''):
            setExpirationDateAction = QAction('Set &Expiration', self)
            setExpirationDateAction.setShortcut('F3')
            setExpirationDateAction.triggered.connect(self.OnClickSetExpiry)
            fileMenu.addAction(setExpirationDateAction)
        fileMenu.addSeparator()
        kerberosAction = QAction('&Kerberos Authentication', self)
        kerberosAction.setShortcut('Ctrl+K')
        kerberosAction.setCheckable(True)
        kerberosAction.setChecked(True)
        kerberosAction.triggered.connect(self.OnClickKerberos)
        fileMenu.addAction(kerberosAction)
        fileMenu.addSeparator()
        quitAction = QAction('&Quit', self)
        quitAction.setShortcut('Ctrl+Q')
        quitAction.triggered.connect(self.OnQuit)
        fileMenu.addAction(quitAction)

        # Connection Menu
        # only available on linux as there is no reasonable way to open remote connections with password on other OSes
        if(self.PLATFORM == 'linux'):
            self.__checkRemoteConnectors()

            if(self.renderConnectMenu == True):
                connectMenu = mainMenu.addMenu('&Connect')

                if(self.useRemmina == True or self.useFreeRdp == True):
                    rdpAction = QAction('&RDP', self)
                    rdpAction.setShortcut('F5')
                    rdpAction.triggered.connect(self.OnClickRDP)
                    connectMenu.addAction(rdpAction)
                if(self.useRemmina == True or self.useSsh == True):
                    sshAction = QAction('&SSH', self)
                    sshAction.setShortcut('F6')
                    sshAction.triggered.connect(self.OnClickSSH)
                    connectMenu.addAction(sshAction)

        # Help Menu
        helpMenu = mainMenu.addMenu('&Help')

        aboutAction = QAction('&About', self)
        aboutAction.setShortcut('F1')
        aboutAction.triggered.connect(self.OnOpenAboutDialog)
        helpMenu.addAction(aboutAction)

        # Statusbar
        self.setStatusBar(self.statusBar())

        # Window Content
        grid = QGridLayout()
        gridLine = 0

        self.lblSearchComputer = QLabel('Computer Name')
        grid.addWidget(self.lblSearchComputer, gridLine, 0)
        gridLine += 1
        self.txtSearchComputer = QLineEdit()
        self.txtSearchComputer.returnPressed.connect(self.OnReturnSearch)
        grid.addWidget(self.txtSearchComputer, gridLine, 0)
        self.btnSearchComputer = QPushButton('Search')
        self.btnSearchComputer.clicked.connect(self.OnClickSearch)
        grid.addWidget(self.btnSearchComputer, gridLine, 1)
        gridLine += 1

        attrs = self.cfg.ldap_attributes.to_dict()
        for key in attrs:
            title = key  # unused
            attribute = attrs[key]
            lblAdditionalAttribute = QLabel(str(title))
            grid.addWidget(lblAdditionalAttribute, gridLine, 0)
            gridLine += 1
            txtAdditionalAttribute = QLineEdit()
            txtAdditionalAttribute.setReadOnly(True)
            if(self.PLATFORM == 'win32'):
                font = QFont('Consolas', 14)
                font.setBold(True)
            else:
                font = QFontDatabase.systemFont(
                    QFontDatabase.SystemFont.FixedFont)
                font.setPointSize(18 if self.PLATFORM == 'darwin' else 14)
            txtAdditionalAttribute.setFont(font)
            grid.addWidget(txtAdditionalAttribute, gridLine, 0)
            gridLine += 1
            self.refLdapAttributesTextBoxes[str(
                title)] = txtAdditionalAttribute

        self.btnSetExpirationTime = QPushButton('Set New Expiration Date')
        self.btnSetExpirationTime.setEnabled(False)
        self.btnSetExpirationTime.clicked.connect(self.OnClickSetExpiry)
        if(self.cfg.ldap_attribute_password_expiry.strip() != ''):
            grid.addWidget(self.btnSetExpirationTime, gridLine, 0)
            gridLine += 1

        widget = QWidget(self)
        widget.setLayout(grid)
        self.setCentralWidget(widget)

        # Window Settings
        self.setMinimumSize(480, 300)
        self.setWindowTitle(self.PRODUCT_NAME + ' v' + self.PRODUCT_VERSION)
        self.statusBar.showMessage('Settings file: ' + self.cfgPath)

        # Handle Parameter - Automatic Search
        urlToHandle: str = ''
        for arg in sys.argv:
            if(arg.startswith(self.PROTOCOL_SCHEME)):
                urlToHandle = arg
        if(urlToHandle != ''):
            print('Handle ' + urlToHandle)
            protocolPayload = unquote(urlToHandle).replace(
                self.PROTOCOL_SCHEME, '').strip(' /')
            self.txtSearchComputer.setText(protocolPayload)
            self.OnClickSearch()

    def OnQuit(self) -> NoReturn:
        sys.exit()

    def OnClickKerberos(self) -> None:
        self.useKerberos = not self.useKerberos

    def OnOpenAboutDialog(self) -> None:
        dlg = LapsAboutWindow(self)
        dlg.exec_()

    def OnReturnSearch(self) -> None:
        self.OnClickSearch()

    def OnClickRDP(self) -> None:
        self.RemoteConnection('RDP')

    def OnClickSSH(self) -> None:
        self.RemoteConnection('SSH')

    def RemoteConnection(self, protocol: Literal['RDP', 'SSH']) -> None:
        if(self.txtSearchComputer.text().strip() == ''):
            return

        password = self.__extractPassword()
        if(password == ''):
            return

        try:
            if(self.useRemmina):
                connector = RemminaConnector(cfgDir=self.cfgDir)
                connResult = connector.connect(
                    computer=self.txtSearchComputer.text(), username=self.cfgUsername, password=password, protocol=protocol)
                self.statusBar.showMessage(connResult)
            else:
                if(self.useFreeRdp):
                    connector = FreeRDPConnector()
                    connector.connect(computer=self.txtSearchComputer.text(),
                                      username=self.cfgUsername, password=password)
                if(self.useSsh):
                    connector = SshConnector()
                    connector.connect(computer=self.txtSearchComputer.text(),
                                      username=self.cfgUsername, password=password)

        except Exception as e:
            # display error
            self.statusBar.showMessage(str(e))
            print(str(e))

    def __extractPassword(self) -> str:
        password = ''
        attrs = self.cfg.ldap_attributes.to_dict()
        for key in attrs:
            title = key
            attribute = attrs[key]
            if(self.cfg.ldap_attribute_password == attribute):  # TODO: Why do we need this control?
                if(title in self.refLdapAttributesTextBoxes):
                    password = self.refLdapAttributesTextBoxes[title].text(
                    )

        return password

    def OnClickSearch(self) -> None:
        # check and escape input
        computerName = self.txtSearchComputer.text()
        if computerName.strip() == "":
            return
        computerName = escape_filter_chars(computerName)

        # ask for credentials
        self.btnSearchComputer.setEnabled(False)
        if not self.checkCredentialsAndConnect():
            self.btnSearchComputer.setEnabled(True)
            return

        try:
            # start LDAP search
            self.connection.search(
                search_base=self.createLdapBase(self.cfgDomain),
                search_filter='(&(objectCategory=computer)(name=' +
                computerName + '))',
                attributes=['SAMAccountname', 'distinguishedName']
            )
            for entry in self.connection.entries:
                self.statusBar.showMessage(
                    'Found: ' + str(entry['distinguishedName']) + ' (' + str(self.connection.server) + ')')
                self.tmpDn = str(entry['distinguishedName'])
                self.queryAttributes()
                return

            # no result found
            self.statusBar.showMessage(
                'No Result For: ' + computerName + ' (' + str(self.connection.server) + ')')
            attrs = self.cfg.ldap_attributes.to_dict()
            for key in attrs:
                title = key
                attribute = attrs[key]  # unused
                self.refLdapAttributesTextBoxes[str(title)].setText('')
        except Exception as e:
            # display error
            self.statusBar.showMessage(str(e))
            print(str(e))
            # reset connection
            self.server = None
            self.connection = None

        self.tmpDn = ''
        self.btnSetExpirationTime.setEnabled(False)
        self.btnSearchComputer.setEnabled(True)

    def OnClickSetExpiry(self) -> None:
        # check if dn of target computer object is known
        if self.tmpDn.strip() == '':
            return

        dlg = LapsCalendarWindow(self)
        dlg.refMainWindows = self
        dlg.exec_()

    def queryAttributes(self) -> None:
        if(not self.reconnectForAttributeQuery()):
            self.btnSetExpirationTime.setEnabled(False)
            self.btnSearchComputer.setEnabled(True)
            return

        # compile query attributes
        attributes = ['SAMAccountname', 'distinguishedName']
        attrs = self.cfg.ldap_attributes.to_dict()
        for key in attrs:
            title = key
            attribute = attrs[key]
            attributes.append(str(attribute))
        # start LDAP search
        self.connection.search(
            search_base=self.tmpDn,
            search_filter='(objectCategory=computer)',
            attributes=attributes
        )
        # display result
        for entry in self.connection.entries:
            self.btnSetExpirationTime.setEnabled(True)
            self.btnSearchComputer.setEnabled(True)
            attrs = self.cfg.ldap_attributes.to_dict()
            for key in attrs:
                title = key
                attribute = attrs[key]
                textBox = self.refLdapAttributesTextBoxes[str(title)]
                if(str(attribute) == self.cfg.ldap_attribute_password_expiry):
                    try:
                        textBox.setText(str(helpers.filetime_to_dt(
                            int(str(entry[str(attribute)])))))
                    except Exception as e:
                        print(str(e))
                        textBox.setText(str(entry[str(attribute)]))
                else:
                    textBox.setText(str(entry[str(attribute)]))
            return

    def checkCredentialsAndConnect(self) -> bool:
        # ask for server address and domain name if not already set via config file
        if self.cfgDomain == "":
            item, ok = QInputDialog.getText(
                self, '♕ Domain', 'Please enter your Domain name (e.g. example.com).')
            if ok and item:
                self.cfgDomain = item
                self.server = None
            else:
                return False
        if len(self.cfg.server) == 0:
            # query domain controllers by dns lookup
            try:
                res: resolver.Answer = resolver.query(
                    qname=f"_ldap._tcp.{self.cfgDomain}", rdtype=rdatatype.SRV, lifetime=10)
                for srv in res.rrset:  # type: ignore
                    serverEntry = CfgServer(
                        str(srv.target), srv.port, (srv.port == 636))
                    print('DNS auto discovery found server: ' +
                          json.dumps(serverEntry))
                    self.cfg.server.append(serverEntry)
            except Exception as e:
                print('DNS auto discovery failed: ' + str(e))
            # ask user to enter server names if auto discovery was not successful
            if len(self.cfg.server) == 0:
                item, ok = QInputDialog.getText(
                    self, '💻 Server Address', 'Please enter your LDAP server IP address or DNS name.')
                if ok and item:
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
                self.showErrorDialog('Error connecting to LDAP server', str(e))
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
        sslHint = ''
        if len(self.cfg.server) > 0 and self.cfg.server[0].ssl == False:
            sslHint = '\n\nPlease consider enabling SSL in the config file (~/.config/laps-client/settings.json).'
        if self.cfgUsername == "":
            item, ok = QInputDialog.getText(self, '👤 Username', 'Please enter the username which should be used to connect to:\n' + str(
                self.cfg.server), QLineEdit.Normal, getpass.getuser())
            if ok and item:
                self.cfgUsername = item
                self.connection = None
            else:
                return False
        if self.cfgPassword == "":
            item, ok = QInputDialog.getText(self, '🔑 Password for »' + self.cfgUsername + '«',
                                            'Please enter the password which should be used to connect to:\n' + str(self.cfg.server) + sslHint, QLineEdit.Password)
            if ok and item:
                self.cfgPassword = item
                self.connection = None
            else:
                return False
        self.SaveSettings()

        # try to bind to server with username and password
        try:
            self.connection = ldap3.Connection(
                self.server,
                user=self.cfgUsername + '@' + self.cfgDomain,
                password=self.cfgPassword,
                authentication=ldap3.SIMPLE,
                auto_referrals=True,
                auto_bind='DEFAULT'
            )
            # self.connection.bind()
        except Exception as e:
            self.cfgUsername = ''
            self.cfgPassword = ''
            self.showErrorDialog('Error binding to LDAP server', str(e))
            return False

        return True  # return if connection created successfully

    def reconnectForAttributeQuery(self) -> bool:
        # global catalog was not used for search - we can use the same connection for attribute query
        if(not self.gcModeOn):
            return True
        # global catalog was used for search (this buddy is read only and not all attributes are replicated into it)
        # -> that's why we need to establish a new connection to the "normal" LDAP port
        # LDAP referrals to the correct (sub)domain controller is handled automatically by ldap3
        serverArray = []
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
                                               user=self.cfgUsername + '@' + self.cfgDomain,
                                               password=self.cfgPassword,
                                               authentication=ldap3.SIMPLE,
                                               auto_referrals=True,
                                               auto_bind='DEFAULT'
                                               )
            return True
        except Exception as e:
            self.showErrorDialog('Error binding to LDAP server', str(e))
            return False

    def createLdapBase(self, domain: str) -> str:
        # convert FQDN "example.com" to LDAP path notation "DC=example,DC=com"
        search_base: str = ""
        base = domain.split(".")
        for b in base:
            search_base += "DC=" + b + ","
        return search_base[:-1]

    def showErrorDialog(self, title: str, text: str, additionalText: str = '') -> None:
        print('Error: ' + text)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setDetailedText(additionalText)
        msg.setStandardButtons(QMessageBox.Ok)
        retval = msg.exec_()

    def showInfoDialog(self, title: str, text: str, additionalText: str = '') -> None:
        print('Info: ' + text)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setDetailedText(additionalText)
        msg.setStandardButtons(QMessageBox.Ok)
        retval = msg.exec_()

    def __checkRemoteConnectors(self) -> None:
        if(which('remmina') is not None):
            self.useRemmina = True
            self.renderConnectMenu = True
        else:
            if(which('xfreerdp')):
                self.useFreeRdp = True
                self.renderConnectMenu = True
            if(which('ssh')):
                self.useSsh = True
                self.renderConnectMenu = True


class LapsAboutWindow(QDialog):
    def __init__(self, *args, **kwargs) -> None:
        super(LapsAboutWindow, self).__init__(*args, **kwargs)
        self.InitUI()

    def InitUI(self) -> None:
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        self.buttonBox.accepted.connect(
            self.accept)  # This line throws an error

        layout = QVBoxLayout(self)

        labelAppName = QLabel(self)
        labelAppName.setText(self.parentWidget().PRODUCT_NAME +
                             " v" + self.parentWidget().PRODUCT_VERSION)
        labelAppName.setStyleSheet("font-weight:bold")
        labelAppName.setAlignment(Qt.AlignCenter)
        layout.addWidget(labelAppName)

        labelCopyright = QLabel(self)
        labelCopyright.setText(
            "<br>"
            "© 2021-2022 <a href='https://georg-sieber.de'>Georg Sieber</a>"
            "<br>"
            "<br>"
            "GNU General Public License v3.0"
            "<br>"
            "<a href='" + self.parentWidget().PRODUCT_WEBSITE + "'>" +
            self.parentWidget().PRODUCT_WEBSITE + "</a>"
            "<br>"
            "<br>"
            "If you like LAPS4LINUX please consider<br>making a donation to support further development."
            "<br>"
        )
        labelCopyright.setOpenExternalLinks(True)
        labelCopyright.setAlignment(Qt.AlignCenter)
        layout.addWidget(labelCopyright)

        labelDescription = QLabel(self)
        labelDescription.setText(
            """LAPS4LINUX client allows you to query local administrator passwords for LAPS runner managed workstations in your domain from your LDAP (Active Directory) server.\n\n"""
            """The LAPS runner periodically sets a new administrator password and saves it into the LDAP directory.\n\n"""
            """LAPS was originally developed by Microsoft, this is an inofficial Linux/Unix implementation with some enhancements (e.g. the CLI/GUI client can display additional attributes)."""
        )
        labelDescription.setStyleSheet("opacity:0.8")
        labelDescription.setFixedWidth(450)
        labelDescription.setWordWrap(True)
        layout.addWidget(labelDescription)

        layout.addWidget(self.buttonBox)

        self.setLayout(layout)
        self.setWindowTitle("About")

    def parentWidget(self) -> LapsMainWindow:
        return typing.cast(LapsMainWindow, super().parentWidget())


class LapsCalendarWindow(QDialog):
    def __init__(self, *args, **kwargs) -> None:
        super(LapsCalendarWindow, self).__init__(*args, **kwargs)
        self.InitUI()

    def InitUI(self) -> None:
        buttons = QDialogButtonBox.StandardButton(
        ).Ok | QDialogButtonBox.StandardButton.Cancel
        std = QDialogButtonBox.StandardButtons()
        self.buttonBox = QDialogButtonBox()
        self.buttonBox.setStandardButtons(std | typing.cast(
            QDialogButtonBox.StandardButton, buttons))
        self.buttonBox.accepted.connect(self.OnClickAccept)
        self.buttonBox.rejected.connect(self.OnClickReject)

        layout = QVBoxLayout(self)
        self.cwNewExpirationTime = QCalendarWidget()
        layout.addWidget(self.cwNewExpirationTime)

        layout.addWidget(self.buttonBox)

        self.setLayout(layout)
        self.setWindowTitle("Set New Expiration Date")

    def parentWidget(self) -> LapsMainWindow:
        return typing.cast(LapsMainWindow, super().parentWidget())

    def OnClickAccept(self) -> None:
        parentWidget = self.parentWidget()

        # check if dn of target computer object is known
        if parentWidget.tmpDn.strip() == '':
            return

        try:
            # calc new time
            newExpirationDate = datetime.combine(
                self.cwNewExpirationTime.selectedDate().toPyDate(), datetime.min.time())
            newExpirationDateTime = helpers.dt_to_filetime(newExpirationDate)
            print('new expiration time: ' + str(newExpirationDateTime))

            # start LDAP modify
            parentWidget.connection.modify(parentWidget.tmpDn, {parentWidget.cfg.ldap_attribute_password_expiry: [
                                           (ldap3.MODIFY_REPLACE, [str(newExpirationDateTime)])]})
            if parentWidget.connection.result['result'] == 0:
                parentWidget.showInfoDialog('Success',
                                            'Expiration date successfully changed to ' +
                                            str(newExpirationDate) + '.',
                                            parentWidget.tmpDn +
                                            ' (' + str(parentWidget.connection.server) + ')'
                                            )
                # update values in main window
                parentWidget.OnClickSearch()
                self.close()
            else:
                parentWidget.showErrorDialog('Error', 'Unable to change expiration date to ' + str(newExpirationDateTime) + '.' + "\n\n" + str(
                    parentWidget.connection.result['message']), parentWidget.tmpDn + ' (' + str(parentWidget.connection.server) + ')')

        except Exception as e:
            # display error
            parentWidget.showErrorDialog(
                'Error setting new expiration date', str(e))
            # reset connection
            parentWidget.server = None
            parentWidget.connection = None

    def OnClickReject(self) -> None:
        self.close()


def main() -> NoReturn:
    app = QApplication(sys.argv)
    window = LapsMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
