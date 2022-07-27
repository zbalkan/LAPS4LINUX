from typing import List
from typing import Any
from dataclasses import dataclass


@dataclass
class Server:
    address: str
    port: int
    ssl: bool

    @staticmethod
    def from_dict(obj: Any) -> 'Server':
        _address = str(obj.get("address"))
        _port = int(obj.get("port"))
        _ssl = False
        return Server(_address, _port, _ssl)


@dataclass
class RunnerConfig:
    server: List[Server]
    domain: str
    cred_cache_file: str
    client_keytab_file: str
    ldap_attribute_password: str
    ldap_attribute_password_expiry: str
    hostname: str
    password_change_user: str
    password_days_valid: int
    password_length: int
    password_alphabet: str

    @staticmethod
    def from_dict(obj: Any) -> 'RunnerConfig':
        _server = [Server.from_dict(y) for y in obj.get("server")]
        _domain = str(obj.get("domain"))
        _cred_cache_file = str(obj.get("cred-cache-file"))
        _client_keytab_file = str(obj.get("client-keytab-file"))
        _ldap_attribute_password = str(obj.get("ldap-attribute-password"))
        _ldap_attribute_password_expiry = str(
            obj.get("ldap-attribute-password-expiry"))
        _hostname = str(obj.get("hostname"))
        _password_change_user = str(obj.get("password-change-user"))
        _password_days_valid = int(obj.get("password-days-valid"))
        _password_length = int(obj.get("password-length"))
        _password_alphabet = str(obj.get("password-alphabet"))
        return RunnerConfig(_server, _domain, _cred_cache_file, _client_keytab_file, _ldap_attribute_password, _ldap_attribute_password_expiry, _hostname, _password_change_user, _password_days_valid, _password_length, _password_alphabet)


# Example Usage
# jsonstring = json.loads(myjsonstring)
# RunnerConfig = RunnerConfig.from_dict(jsonstring)
