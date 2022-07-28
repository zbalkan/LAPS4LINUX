import base64
import configparser
import os
import subprocess
import time
from pathlib import Path
from typing import Literal

from Crypto.Cipher import DES3


class RemminaConnector():

    cfgDir: str = ''
    cfgPathRemmina: str = cfgDir + '/laps.remmina'
    safePath: str

    def __init__(self, cfgDir: str) -> None:
        self.cfgDir = cfgDir
        self.safePath = which('xfreerdp')  # type: ignore

    def connect(self, computer: str, username: str, password: str, protocol: Literal['RDP', 'SSH']) -> str:
        # passwords must be encrypted in remmina connection files using the secret found in remmina.pref
        remminaPrefPath = str(Path.home()) + '/.remmina/remmina.pref'
        if(os.path.exists(remminaPrefPath)):
            config = configparser.ConfigParser()
            config.read(remminaPrefPath)

            if(config.has_section('remmina_pref') and 'secret' in config['remmina_pref'] and config['remmina_pref']['secret'].strip() != ''):
                secret = base64.b64decode(config['remmina_pref']['secret'])
                padding = chr(0) * (8 - len(password) % 8)
                password = base64.b64encode(DES3.new(secret[:24], DES3.MODE_CBC, secret[24:]).encrypt((
                    password + padding).encode('utf-8'))).decode('utf-8')
            else:
                password = ''
                return(
                    'Unable to find secret in remmina_pref')
        else:
            password = ''
            return('Unable to find remmina.pref')

        # creating remmina files with permissions 400 is currently useless as remmina re-creates the file with 664 on exit with updated settings
        # protection is done by limiting access to our config dir
        if(protocol == 'RDP'):
            self.__setRdpConfig(computer, username, password)
        elif(protocol == 'SSH'):
            self.__setSshConfig(computer, username, password)

        subprocess.Popen([self.safePath, '-c', self.cfgPathRemmina])
        return "Connection succeeded."

    def __setSshConfig(self, computerName: str, username: str, password: str) -> None:
        with open(os.open(self.cfgPathRemmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
            f.write(
                "[remmina]\n" +
                "name=" + computerName + "\n" +
                "server=" + computerName + "\n" +
                "username=" + username + "\n" +
                "password=" + password + "\n"
                "protocol=SSH\n"
            )
            f.close()
        time.sleep(0.2)

    def __setRdpConfig(self, computerName: str, username: str, password: str) -> None:
        with open(os.open(self.cfgPathRemmina, os.O_CREAT | os.O_WRONLY, 0o400), 'w') as f:
            f.write(
                "[remmina]\n" +
                "name=" + computerName + "\n" +
                "server=" + computerName + "\n" +
                "username=" + username + "\n" +
                "password=" + password + "\n"
                "protocol=RDP\n" +
                "scale=2\n" +
                "window_width=1092\n" +
                "window_height=720\n" +
                "colordepth=0\n"
            )
            f.close()
        time.sleep(0.2)
