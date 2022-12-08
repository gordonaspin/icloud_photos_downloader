"""Constants"""
from enum import Enum, auto
# For retrying connection after timeouts and errors
MAX_RETRIES = 5
WAIT_SECONDS = 5
CHUNK_SIZE = 32*1024

class ExitCode(Enum):
    EXIT_NORMAL = 0
    EXIT_CLICK_EXCEPTION = 1
    EXIT_CLICK_USAGE = 2
    EXIT_FAILED_SEND_2FA_CODE = auto()
    EXIT_FAILED_VERIFY_2FA_CODE = auto()
    EXIT_FAILED_MISSING_COMMAND = auto()
    EXIT_FAILED_LOGIN = auto()
    EXIT_FAILED_CLOUD_API = auto()
    EXIT_FAILED_2FA_REQUIRED  = auto()