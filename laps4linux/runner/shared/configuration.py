from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class CfgServer:
    address: str
    port: int
    gc_port: Optional[int]
    ssl: bool

    def __init__(self, address: str, port: int, ssl: bool, gc_port: Optional[int] = None) -> None:
        self.address = address
        self.port = port
        self.gc_port = gc_port
        self.ssl = ssl

    @staticmethod
    def from_dict(obj: Any) -> 'CfgServer':
        _address: str = str(obj.get("address"))
        _port: int = int(obj.get("port"))
        _gc_port: int = int(obj.get("port"))
        _ssl: bool = False
        return CfgServer(_address, _port, _ssl, _gc_port)


@dataclass
class RunnerConfig:
    server: List[CfgServer]
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
        _server: list[CfgServer] = [
            CfgServer.from_dict(y) for y in obj.get("server")]
        _domain: str = str(obj.get("domain"))
        _cred_cache_file: str = str(obj.get("cred-cache-file"))
        _client_keytab_file: str = str(obj.get("client-keytab-file"))
        _ldap_attribute_password: str = str(obj.get("ldap-attribute-password"))
        _ldap_attribute_password_expiry: str = str(
            obj.get("ldap-attribute-password-expiry"))
        _hostname: str = str(obj.get("hostname"))
        _password_change_user: str = str(obj.get("password-change-user"))
        _password_days_valid: int = int(obj.get("password-days-valid"))
        _password_length: int = int(obj.get("password-length"))
        _password_alphabet: str = str(obj.get("password-alphabet"))
        return RunnerConfig(_server, _domain, _cred_cache_file, _client_keytab_file, _ldap_attribute_password, _ldap_attribute_password_expiry, _hostname, _password_change_user, _password_days_valid, _password_length, _password_alphabet)


@dataclass
class CfgLdapAttributes:
    OperatingSystem: str
    lastLogonTimestamp: str
    AdministratorPassword: str
    PasswordExpirationDate: str

    @staticmethod
    def from_dict(obj: Any) -> 'CfgLdapAttributes':
        _OperatingSystem: str = str(obj.get("Operating System"))
        _lastLogonTimestamp: str = str(obj.get("lastLogonTimestamp"))
        _AdministratorPassword: str = str(obj.get("Administrator Password"))
        _PasswordExpirationDate: str = str(obj.get("Password Expiration Date"))
        return CfgLdapAttributes(_OperatingSystem, _lastLogonTimestamp, _AdministratorPassword, _PasswordExpirationDate)

    def to_dict(self) -> dict[str, str]:
        return {
            "Operating System": self.OperatingSystem,
            "lastLogonTimestamp": self.lastLogonTimestamp,
            "Administrator Password": self.AdministratorPassword,
            "Password Expiration Date": self.PasswordExpirationDate
        }


@dataclass
class ClientConfig:
    server: List[CfgServer]
    domain: str
    username: str
    ldap_attribute_password: str
    ldap_attribute_password_expiry: str
    ldap_attributes: CfgLdapAttributes

    @staticmethod
    def from_dict(obj: Any) -> 'ClientConfig':
        _server: list[CfgServer] = [
            CfgServer.from_dict(y) for y in obj.get("server")]
        _domain: str = str(obj.get("domain"))
        _username: str = str(obj.get("username"))
        _ldap_attribute_password: str = str(obj.get("ldap-attribute-password"))
        _ldap_attribute_password_expiry: str = str(
            obj.get("ldap-attribute-password-expiry"))
        _ldap_attributes: CfgLdapAttributes = CfgLdapAttributes.from_dict(
            obj.get("ldap-attributes"))
        return ClientConfig(_server, _domain, _username, _ldap_attribute_password, _ldap_attribute_password_expiry, _ldap_attributes)
