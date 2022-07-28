
import subprocess
from shutil import which


class FreeRDPConnector():

    safePath: str

    def __init__(self) -> None:
        self.safePath = which('xfreerdp')  # type: ignore

    def connect(self, computer: str, username: str, password: str) -> str:
        subprocess.Popen([self.safePath, '/u:', username,
                         '/p:', password, '/v:', computer, ' /dynamic-resolution', '/cert:ignore'])
        return "Connection succeeded."
