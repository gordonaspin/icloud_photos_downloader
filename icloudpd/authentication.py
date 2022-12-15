"""Handles username/password authentication and two-step authentication"""

import sys
import click
import logging

import pyicloud
from icloudpd.logger import setup_logger
import icloudpd.constants as constants
import pyicloud.utils as utils
from pyicloud.exceptions import PyiCloud2SARequiredException
from pyicloud.exceptions import PyiCloudFailedLoginException
from pyicloud.exceptions import PyiCloudNoStoredPasswordAvailableException

def authenticate(
    username,
    password,
    cookie_directory=None,
    raise_exception_on_2sa=False,
    client_id=None
):
    """Authenticate with iCloud username and password"""
    logger = setup_logger()
    logger.debug("Authenticating...")

    if not raise_exception_on_2sa and not sys.stdout.isatty():
        logger.debug(f"raise_exception_on_2sa is {raise_exception_on_2sa}, but stdout is not a tty, forcing raise_exception_on_2sa to True")
        raise_exception_on_2sa = True

    failure_count = 0
    try:
        api = pyicloud.PyiCloudService(
            username,
            password,
            cookie_directory=cookie_directory,
            client_id=client_id)
            
        if api.requires_2fa:
            # fmt: off
            print(
                "\nTwo-factor (2FA) authentication required.",
                "\nPlease enter validation code"
            )
            # fmt: on
            if raise_exception_on_2sa:
                raise PyiCloud2SARequiredException

            code = input("(string) --> ")
            if not api.validate_2fa_code(code):
                logger.debug("Failed to verify (2FA) verification code")
                sys.exit(constants.ExitCode.EXIT_FAILED_VERIFY_2FA_CODE.value)
                
        elif api.requires_2sa:
            # fmt: off
            print(
                "\nTwo-step (2SA) authentication required.",
                "\nYour trusted devices are:"
            )
            # fmt: on
            if raise_exception_on_2sa:
                raise PyiCloud2SARequiredException

            devices = api.trusted_devices
            for i, device in enumerate(devices):
                print(
                    "    %s: %s"
                    % (
                        i,
                        device.get(
                            "deviceName", "SMS to %s" % device.get("phoneNumber")
                        ),
                    )
                )

            print("\nWhich device would you like to use?")
            device = int(input("(number) --> "))
            device = devices[device]
            if not api.send_verification_code(device):
                logger.debug("Failed to send verification code")
                sys.exit(constants.ExitCode.EXIT_FAILED_SEND_2SA_CODE)

            print("\nPlease enter two-step (2SA) validation code")
            code = input("(string) --> ")
            if not api.validate_verification_code(device, code):
                print("Failed to verify verification code")
                sys.exit(constants.ExitCode.EXIT_FAILED_VERIFY_2FA_CODE)
        # Auth success
        logger.info(f"Authenticated as {username}")
        return api

    except PyiCloudFailedLoginException as err:
        # If the user has a stored password; we just used it and
        # it did not work; let's delete it if there is one.
        if utils.password_exists_in_keyring(username):
            utils.delete_password_in_keyring(username)

        message = "Bad username or password for {username}".format(username=username)
        failure_count += 1
        if failure_count >= constants.AUTHENTICATION_MAX_RETRIES:
            raise PyiCloudFailedLoginException(message)

        logger.info(message)

    except PyiCloudNoStoredPasswordAvailableException:
       # Prompt for password if not stored in PyiCloud's keyring
        password = click.prompt("iCloud Password", hide_input=True)
        api = pyicloud.PyiCloudService(
                            username, password,
                            cookie_directory=cookie_directory,
                            client_id=client_id)
        if (
            not utils.password_exists_in_keyring(username)
            and sys.stdout.isatty()
            and click.confirm("Save password in keyring?")
        ):
            utils.store_password_in_keyring(username, password)




def old_authenticate(
        username,
        password,
        cookie_directory=None,
        raise_error_on_2sa=False,
        client_id=None
):
    """Authenticate with iCloud username and password"""
    logger = setup_logger()
    logger.debug("Authenticating...")
    try:
        # If password not provided on command line variable will be set to None
        # and PyiCloud will attempt to retrieve from it's keyring
        icloud = pyicloud.PyiCloudService(
            username, password,
            cookie_directory=cookie_directory,
            client_id=client_id)
    except pyicloud.exceptions.PyiCloudNoStoredPasswordAvailableException:
        # Prompt for password if not stored in PyiCloud's keyring
        password = click.prompt("iCloud Password", hide_input=True)
        icloud = pyicloud.PyiCloudService(
            username, password,
            cookie_directory=cookie_directory,
            client_id=client_id)

    if icloud.requires_2sa:
        if raise_error_on_2sa:
            raise PyiCloud2SARequiredException(
                "Two-step/two-factor authentication is required!"
            )
        logger.info("Two-step/two-factor authentication is required!")
        request_2sa(icloud, logger)
    return icloud


def request_2sa(icloud, logger):
    """Request two-step authentication. Prompts for SMS or device"""
    devices = icloud.trusted_devices
    devices_count = len(devices)
    logger.debug(f"request_2sa() devices_count: {devices_count}, devices: {devices}")
    device_index = 0
    if devices_count > 0:
        for i, device in enumerate(devices):
            print(
                "  %s: %s" %
                (i, device.get(
                    "deviceName", "SMS to %s" %
                    device.get("phoneNumber"))))

        # pylint: disable-msg=superfluous-parens
        print("  %s: Enter two-factor authentication code" % devices_count)
        # pylint: enable-msg=superfluous-parens
        device_index = click.prompt(
            "Please choose an option:",
            default=0,
            type=click.IntRange(
                0,
                devices_count))

    if device_index == devices_count:
        # We're using the 2FA code that was automatically sent to the user's device,
        # so can just use an empty dict()
        device = dict()
    else:
        device = devices[device_index]
        if not icloud.send_verification_code(device):
            logger.error("Failed to send two-factor authentication code")
            sys.exit(constants.ExitCode.EXIT_FAILED_SEND_2FA_CODE.value)

    code = click.prompt("Please enter two-factor authentication code")
    if not icloud.validate_verification_code(device, code):
        logger.error("Failed to verify two-factor authentication code")
        sys.exit(constants.ExitCode.EXIT_FAILED_VERIFY_2FA_CODE.value)
    logger.info(
        "Great, you're all set up. The script can now be run without "
        "user interaction until 2SA expires.\n"
        "You can set up email notifications for when "
        "the two-step authentication expires.\n"
        "(Use --help to view information about SMTP options.)"
    )
