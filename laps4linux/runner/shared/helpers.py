# dt.timestamp() returns UTC time as expected by the LDAP server
from datetime import datetime

import constants as const


def dt_to_filetime(dt: datetime) -> int:
    return int((dt.timestamp() + const.EPOCH_TIMESTAMP) * const.HUNDREDS_OF_NANOSECONDS)


# ft is in UTC, fromtimestamp() converts to local time
def filetime_to_dt(ft: int) -> datetime:
    return datetime.fromtimestamp(int((ft / const.HUNDREDS_OF_NANOSECONDS) - const.EPOCH_TIMESTAMP))
