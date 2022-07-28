import subprocess
from shutil import which
import clipboard


class SshConnector():
    safePath: str

    def __init__(self) -> None:
        self.safePath = which('ssh')  # type: ignore

    def connect(self, computer: str, username: str, password: str, port: int = 22) -> str:
        clipboard.copy(password)
        subprocess.Popen([self.safePath, username + '@' +
                         computer, '-p', str(port)])
        return "Connection succeeded."
