#!/usr/bin/env python
"""Main script that uses Click to parse command-line arguments"""
from __future__ import print_function

import datetime
import itertools
import json
import logging
import os
import subprocess
import sys
import time
import hashlib

import click
import urllib3

from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(category=InsecureRequestWarning)

from pyicloud.exceptions import (PyiCloud2SARequiredException,
                                 PyiCloudAPIResponseException,
                                 PyiCloudFailedLoginException)
from tqdm import tqdm
from tzlocal import get_localzone

# Must import the constants object so that we can mock values in tests.
import icloudpd.constants as constants
from icloudpd import download, exif_datetime
from icloudpd.authentication import authenticate
from icloudpd.autodelete import autodelete_photos
from icloudpd.email_notifications import send_2sa_notification
from icloudpd.logger import setup_logger
from icloudpd.logger import setup_database_logger
from icloudpd.paths import build_download_dir, local_download_path
from icloudpd.string_helpers import truncate_middle
import icloudpd.database as database

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.command(context_settings=CONTEXT_SETTINGS, options_metavar="<options>")
# @click.argument(
@click.option("-d", "--directory",     help="Local directory that should be used for download", type=click.Path(exists=True), metavar="<directory>")
@click.option("-u", "--username",      help="Your iCloud username or email address", metavar="<username>")
@click.option("-p", "--password",      help="Your iCloud password (default: use PyiCloud keyring or prompt for password)", metavar="<password>")
@click.option("--cookie-directory",    help="Directory to store cookies for authentication (default: ~/.pyicloud)", metavar="</cookie/directory>", default="~/.pyicloud")
@click.option("--size",                help="Image size to download (default: original)", type=click.Choice(["original", "medium", "thumb"]), default="original")
@click.option("--live-photo-size",     help="Live Photo video size to download (default: original)", type=click.Choice(["original", "medium", "thumb"]), default="original")
@click.option("--recent",              help="Number of recent photos to download (default: download all photos)", type=click.IntRange(0))
@click.option('--date-since',          help="Download only assets newer than date-since", type=click.DateTime(formats=["%Y-%m-%d", "%Y-%m-%d-%H:%M:%S"]))
@click.option('--newest',              help="Download only assets newer than newest asset date from local icloudpd.db. Will override --date-since value.", is_flag=True)
@click.option("--until-found",         help="Download most recently added photos until we find x number of previously downloaded consecutive photos (default: download all photos)", type=click.IntRange(0))
@click.option("-a", "--album",         help="Album to download (default: All Photos)", metavar="<album>", default="All Photos")
@click.option("--all-albums",          help="Download all albums", is_flag=True)
@click.option("--skip-smart-folders",  help="Exclude smart folders from listing or download: All Photos, Time-lapse, Videos, Slo-mo, Bursts, Favorites, Panoramas, Screenshots, Live, Recently Deleted, Hidden", is_flag=True)
@click.option("--skip-All-Photos",     help="Exclude the smart folders 'All Photos' from listing or download", is_flag=True)
@click.option("-l", "--list-albums",   help="Lists the avaliable albums and exits", is_flag=True)
@click.option("-s", "--sort",          help="Sort album names (default: desc)", type=click.Choice(["asc", "desc"]), default="desc")
@click.option("--skip-videos",         help="Don't download any videos (default: Download all photos and videos)", is_flag=True)
@click.option("--skip-live-photos",    help="Don't download any live photos (default: Download live photos)", is_flag=True,)
@click.option("--force-size",          help="Only download the requested size (default: download original if size is not available)", is_flag=True,)
@click.option("--auto-delete",         help='Scans the "Recently Deleted" folder and deletes any files found in there. (If you restore the photo in iCloud, it will be downloaded again.)', is_flag=True)
@click.option("--only-print-filenames",help="Only prints the filenames of all files that will be downloaded (not including files that are already downloaded). (Does not download or delete any files.)", is_flag=True)
@click.option("--folder-structure",    help="Folder structure (default: {:%Y/%m/%d}). If set to 'none' all photos will just be placed into the download directory, if set to 'album' photos will be placed in a folder named as the album into the download directory", metavar="<folder_structure>", default="{:%Y/%m/%d}",)
@click.option("--list-duplicates",     help="List files that are duplicates by the file content md5 hash", is_flag=True)
@click.option("--create-json-listing", help="Creates a catalog.json file listing of the albums/assets processed in folder specified by directory option", is_flag=True)
@click.option("--set-exif-datetime",   help="Write the DateTimeOriginal exif tag from file creation date, if it doesn't exist.", is_flag=True)
@click.option("--smtp-username",       help="Your SMTP username, for sending email notifications when two-step authentication expires.", metavar="<smtp_username>")
@click.option("--smtp-password",       help="Your SMTP password, for sending email notifications when two-step authentication expires.", metavar="<smtp_password>")
@click.option("--smtp-host",           help="Your SMTP server host. Defaults to: smtp.gmail.com", metavar="<smtp_host>", default="smtp.gmail.com")
@click.option("--smtp-port",           help="Your SMTP server port. Default: 587 (Gmail)", metavar="<smtp_port>", type=click.IntRange(0), default=587)
@click.option("--smtp-no-tls",         help="Pass this flag to disable TLS for SMTP (TLS is required for Gmail)", metavar="<smtp_no_tls>", is_flag=True)
@click.option("--notification-email",  help="Email address where you would like to receive email notifications. Default: SMTP username", metavar="<notification_email>")
@click.option("--notification-script", help="Runs an external script when two factor authentication expires. (path required: /path/to/my/script.sh)", type=click.Path(), )
@click.option("--log-level",           help="Log level (default: debug)", type=click.Choice(["debug", "info", "error"]), default="debug")
@click.option("--no-progress-bar",     help="Disables the one-line progress bar and prints log messages on separate lines (Progress bar is disabled by default if there is no tty attached)", is_flag=True)
@click.option("--unverified-https",    help="Overrides default https context with unverified https context", is_flag=True)

@click.version_option()
# pylint: disable-msg=too-many-arguments,too-many-statements
# pylint: disable-msg=too-many-branches,too-many-locals

def main(
        directory,
        username,
        password,
        cookie_directory,
        size,
        live_photo_size,
        recent,
        date_since,
        newest,
        until_found,
        album,
        all_albums,
        skip_smart_folders,
        skip_all_photos,
        list_albums,
        sort,
        skip_videos,
        skip_live_photos,
        force_size,
        auto_delete,
        only_print_filenames,
        folder_structure,
        list_duplicates,
        create_json_listing,
        set_exif_datetime,
        smtp_username,
        smtp_password,
        smtp_host,
        smtp_port,
        smtp_no_tls,
        notification_email,
        log_level,
        no_progress_bar,
        notification_script,         # pylint: disable=W0613
        unverified_https,
):
    """Download all iCloud photos to a local directory"""
    start = datetime.datetime.now()
    logger = setup_logger()

    if directory:
        database.setup_database(directory)
        setup_database_logger()
        db = database.DatabaseHandler()

    if only_print_filenames or list_albums:
        logger.disabled = True
    else:
        # Need to make sure disabled is reset to the correct value,
        # because the logger instance is shared between tests.
        logger.disabled = False
        if log_level == "debug":
            logger.setLevel(logging.DEBUG)
        elif log_level == "info":
            logger.setLevel(logging.INFO)
        elif log_level == "error":
            logger.setLevel(logging.ERROR)

    logger.info(f"directory: {directory}")
    logger.info(f"username: {username}")
    logger.info(f"cookie_directory: {cookie_directory}")
    logger.info(f"size: {size}")
    logger.info(f"live_photo_size {live_photo_size}")
    logger.info(f"recent: {recent}")
    logger.info(f"date_since: {date_since}")
    logger.info(f"newest: {newest}")
    logger.info(f"until_found: {until_found}")
    logger.info(f"album: {album}")
    logger.info(f"all_albums: {all_albums}")
    logger.info(f"skip_smart_folders: {skip_smart_folders}")
    logger.info(f"skip_all_photos: {skip_all_photos}")
    logger.info(f"list_albums: {list_albums}")
    logger.info(f"sort: {sort}")
    logger.info(f"skip_videos: {skip_videos}")
    logger.info(f"skip_live_photos: {skip_live_photos}")
    logger.info(f"force_size: {force_size}")
    logger.info(f"auto_delete: {auto_delete}")
    logger.info(f"only_print_filenames: {only_print_filenames}")
    logger.info(f"folder_structure: {folder_structure}")
    logger.info(f"list_duplicates: {list_duplicates}")
    logger.info(f"set_exif_datetime: {set_exif_datetime}")
    logger.info(f"smtp_username: {smtp_username}")
    logger.info(f"smtp_password: {smtp_password}")
    logger.info(f"smtp_host: {smtp_host}")
    logger.info(f"smtp_port: {smtp_port}")
    logger.info(f"smtp_no_tls: {smtp_no_tls}")
    logger.info(f"notification_email: {notification_email}")
    logger.info(f"log_level: {log_level}")
    logger.info(f"no_progress_bar: {no_progress_bar}")
    logger.info(f"notification_script: {notification_script}")
    logger.info(f"unverified_https: {unverified_https}")
        
    # check required directory param only if not list albums
    if not list_albums and not directory:
        print('--directory or --list-albums are required')
        sys.exit(constants.ExitCode.EXIT_FAILED_MISSING_COMMAND.value)

    def print_duplicates(duplicates):
        if duplicates:
            duplicate_iter = iter(duplicates)
            size = 0
            while True:
                try:
                    duplicate = next(duplicate_iter)
                    logger.info(f"there are {duplicate['count']} duplicates with md5 {duplicate['md5']} and size {duplicate['size']}:")
                    count = duplicate['count']
                    for i in range(0, count):
                        logger.info(f"duplicate:{duplicate['md5']}: {duplicate['path']}")
                        if i < count - 1:
                            size = size + int(duplicate['size'])
                            duplicate = next(duplicate_iter)

                except StopIteration:
                    if size > 1024*1024*1024:
                        logger.info(f"{size/(1024*1024*1024):.1f} GB could be reclaimed")
                    elif size > 1024*1024:
                        logger.info(f"{size/(1024*1024):.1f} MB could be reclaimed")
                    elif size > 1024:
                        logger.info(f"{size/(1024):.1f} KB could be reclaimed")
                    else:
                        logger.info(f"{size} bytes could be reclaimed")
                    break
        else:
            logger.info("there are no duplicates")
            
    if not username and directory and list_duplicates:
        print_duplicates(db.fetch_duplicates())
        sys.exit(constants.ExitCode.EXIT_NORMAL.value)
            
    raise_authorization_exception = (
        smtp_username is not None
        or notification_email is not None
        or notification_script is not None
        or not sys.stdout.isatty()
    )

    try:
        logger.debug("connecting to iCloudService...")
        #icloud = PyiCloudService(
        icloud = authenticate(
            username,
            password,
            cookie_directory,
            raise_authorization_exception,
            client_id=os.environ.get("CLIENT_ID"),
            unverified_https=unverified_https)
    except PyiCloud2SARequiredException as ex:
        if notification_script is not None:
            logger.debug(f"executing notification script {notification_script}")
            subprocess.call([notification_script])
        if smtp_username is not None or notification_email is not None:
            logger.debug(f"sending 2sa email notification")
            send_2sa_notification(
                smtp_username,
                smtp_password,
                smtp_host,
                smtp_port,
                smtp_no_tls,
                notification_email,
            )
        logger.error(ex)
        sys.exit(constants.ExitCode.EXIT_FAILED_2FA_REQUIRED.value)
    except PyiCloudFailedLoginException as ex:
        logger.error(ex)
        sys.exit(constants.ExitCode.EXIT_FAILED_LOGIN.value)

    # Default album is "All Photos", so this is the same as
    # calling `icloud.photos.all`.
    # After 6 or 7 runs within 1h Apple blocks the API for some time. In that
    # case exit.
    try:
        logger.info(f"fetching library information from iCloudService...")
        photos = icloud.photos.all
    except PyiCloudAPIResponseException as ex:
        # For later: come up with a nicer message to the user. For now take the
        # exception text
        print(ex)
        sys.exit(constants.ExitCode.EXIT_FAILED_CLOUD_API.value)

    albums = icloud.photos.albums.values()
    logger.info(f"there are {len(photos)} assets in {len(albums)} albums in your library")

    album_titles = [str(a) for a in albums]
    album_titles.sort(reverse=(sort == 'desc'))
    if list_albums:
        if skip_smart_folders:
            album_titles = [album for album in album_titles if album not in icloud.photos.SMART_FOLDERS.keys()]
        print(*album_titles, sep="\n")
        sys.exit(constants.ExitCode.EXIT_NORMAL.value)

    directory = os.path.normpath(directory)
    newest_created = datetime.datetime.fromtimestamp(0).astimezone(get_localzone())
    newest_name = "unknown"
    logger.info(f"setting newest asset date to {newest_created} and newest asset name to {newest_name}")

    if date_since is not None:
        date_since = date_since.astimezone(get_localzone())
        logger.info(f"assets older than {date_since} will be skipped (from date-since)")

    if newest:
        # (filename, created)
        newest_asset = db.newest_asset()
        if newest_asset is not None:
            newest_created = newest_asset["created"].astimezone(get_localzone())
            date_since = newest_created
            newest_asset = newest_asset["path"]
            logger.info(f"setting newest asset date to {newest_created} and newest asset name to {newest_asset}")
            logger.info(f"assets older than {date_since} will be skipped (from database)")
        else:
            logger.info(f"newest asset date not found in database")

    def photos_exception_handler(ex, retries):
        """Handles session errors in the PhotoAlbum photos iterator"""
        nonlocal icloud
        if "Invalid global session" in str(ex):
            if retries > constants.DOWNLOAD_MEDIA_MAX_RETRIES:
                logger.tqdm_write("iCloud re-authentication failed! Please try again later.")
                raise ex
            logger.tqdm_write("Session error, re-authenticating...", logging.ERROR)
            if retries > 1:
                # If the first reauthentication attempt failed,
                # start waiting a few seconds before retrying in case
                # there are some issues with the Apple servers
                time.sleep(constants.DOWNLOAD_MEDIA_RETRY_CONNECTION_WAIT_SECONDS * retries)
            icloud = authenticate(username, password)
        else:
            if retries > constants.DOWNLOAD_MEDIA_MAX_RETRIES:
                logger.tqdm_write(f"photos_exception_handler: giving up: {ex}")
                raise ex
            logger.tqdm_write(f"photos_exception_handler: retrying: {ex}", logging.ERROR)
            time.sleep(constants.DOWNLOAD_MEDIA_RETRY_CONNECTION_WAIT_SECONDS)


    def download_album(album):
        def download_photo(photo):
            """internal function for actually downloading the photos"""

            nonlocal reached_date_since
            nonlocal consecutive_files_found

            def calculate_md5(path):
                with open(path, 'rb') as f:
                    data = f.read()    
                    return hashlib.md5(data).hexdigest()

            if skip_videos and photo.item_type != "image":
                logger.set_tqdm_description(f"{album}: skipping {photo.filename}, only downloading photos.")
                return
            if photo.item_type != "image" and photo.item_type != "movie":
                logger.set_tqdm_description(f"{album}: skipping {photo.filename}, only downloading photos and videos. (Item type was: {photo.item_type})")
                return
            
            try:
                created_date = photo.created.astimezone(get_localzone())
            except (ValueError, OSError):
                logger.set_tqdm_description(f"{album}: Could not convert photo {photo.filename} created date to local timezone ({photo.created})", logging.ERROR)
                created_date = photo.created

            download_dir = build_download_dir(directory, folder_structure, album, created_date, datetime.datetime.fromtimestamp(0))
            download_size = size

            try:
                versions = photo.versions
            except KeyError as ex:
                print(f"KeyError: {ex} attribute was not found in the photo fields!")
                with open('icloudpd-photo-error.json', 'w') as outfile:
                    # pylint: disable=protected-access
                    json.dump({
                        "master_record": photo._master_record,
                        "asset_record": photo._asset_record
                    }, outfile)
                    # pylint: enable=protected-access
                print("icloudpd has saved the photo record to: "
                    "./icloudpd-photo-error.json")
                print("Please create a Gist with the contents of this file: "
                    "https://gist.github.com")
                print(
                    "Then create an issue on GitHub: "
                    "https://github.com/icloud-photos-downloader/icloud_photos_downloader/issues")
                print(
                    "Include a link to the Gist in your issue, so that we can "
                    "see what went wrong.\n")
                return

            if size not in versions and size != "original":
                if force_size:
                    filename = photo.filename.encode("utf-8").decode("ascii", "ignore")
                    logger.set_tqdm_description(f"{album}: {size} size does not exist for {filename}. skipping...", logging.ERROR)
                    return
                download_size = "original"

            if date_since is not None:
                if created_date < date_since:
                    logger.debug(f"{album}: reached date since {date_since} on {photo.filename.encode('utf-8').decode('ascii', 'ignore')} dated {created_date}")
                    reached_date_since = True
                    return

            download_path = local_download_path(photo, download_size, download_dir)

            file_exists = os.path.isfile(download_path)
            if not file_exists and download_size == "original":
                # Deprecation - We used to download files like IMG_1234-original.jpg,
                # so we need to check for these.
                # Now we match the behavior of iCloud for Windows: IMG_1234.jpg
                original_download_path = f"-{size}.".join(download_path.rsplit(".", 1))
                #original_download_path = ("-%s." % size).join(download_path.rsplit(".", 1))
                file_exists = os.path.isfile(original_download_path)

            if file_exists:
                # for later: this crashes if download-size medium is specified
                file_size = os.stat(download_path).st_size
                version = photo.versions[download_size]
                photo_size = version["size"]
                if file_size != photo_size:
                    download_path = f"-{photo_size}.".join(download_path.rsplit(".", 1))
                    logger.set_tqdm_description(f"{album}: deduplicated (size) {truncate_middle(download_path[len(directory)+1:], 96)} file size {file_size} photo size {photo_size} dated {created_date}")
                    file_exists = os.path.isfile(download_path)
                if file_exists:
                    consecutive_files_found = consecutive_files_found + 1
                    logger.set_tqdm_description(f"{album}: skipping (already exists) {truncate_middle(download_path[len(directory)+1:], 96)} dated {created_date}")
                    if not db.asset_exists(download_path[len(directory)+1:]):
                        md5 = calculate_md5(download_path)
                        logger.info(f"{album}: updating {download_path[len(directory)+1:]} md5 {md5}")
                    else:
                        md5 = db.get_asset_md5(download_path[len(directory)+1:])
                    photo_metadata = db.upsert_asset(album, photo, download_path[len(directory)+1:], md5)
                    photo_metadata['file_size'] = os.stat(download_path).st_size
                    # TODO: Check for multiple occurrences of same asset in iCloud Photos library (happened with WhatsApp)

            if not file_exists:
                consecutive_files_found = 0
                if only_print_filenames:
                    print(download_path)
                else:
                    logger.set_tqdm_description(f"{album}: downloading {truncate_middle(download_path[len(directory)+1:], 96)} dated {created_date}")
                    download_result = download.download_media(icloud, photo, download_path, download_size)
                    if download_result:
                        if set_exif_datetime and photo.filename.lower().endswith(
                                (".jpg", ".jpeg")) and not exif_datetime.get_photo_exif(download_path):
                            # %Y:%m:%d looks wrong but it's the correct format
                            date_str = created_date.strftime("%Y-%m-%d %H:%M:%S%z")
                            logger.debug(f"{album}: setting EXIF timestamp for {download_path[len(directory)+1:]}: {date_str}")
                            exif_datetime.set_photo_exif(download_path, created_date.strftime("%Y:%m:%d %H:%M:%S"))
                        download.set_utime(download_path, created_date)
                        md5 = calculate_md5(download_path)
                        photo_metadata = db.upsert_asset(album, photo, download_path[len(directory)+1:], md5)
                        photo_metadata['file_size'] = os.stat(download_path).st_size


            # Also download the live photo if present
            if not skip_live_photos:
                lp_size = live_photo_size + "Video"
                if lp_size in photo.versions:
                    version = photo.versions[lp_size]
                    filename = version["filename"]
                    if live_photo_size != "original":
                        # Add size to filename if not original
                        filename = filename.replace(".MOV", f"-{live_photo_size}.MOV")
                    lp_download_path = os.path.join(download_dir, filename)
                    lp_file_exists = os.path.isfile(lp_download_path)
                    if only_print_filenames and not lp_file_exists:
                        print(lp_download_path)
                    else:
                        if lp_file_exists:
                            lp_file_size = os.stat(lp_download_path).st_size
                            lp_photo_size = version["size"]
                            if lp_file_size != lp_photo_size:
                                lp_download_path = f"-{lp_photo_size}.".join(lp_download_path.rsplit(".", 1))
                                logger.set_tqdm_description(f"{album}: deduplicated (live) {truncate_middle(lp_download_path[len(directory)+1:], 96)} file size {lp_file_size} photo size {lp_photo_size} dated {created_date}")
                                lp_file_exists = os.path.isfile(lp_download_path)
                            if lp_file_exists:
                                logger.set_tqdm_description(f"{album}: skipping (already exists) {truncate_middle(lp_download_path[len(directory)+1:], 96)} dated {created_date}")
                                if not db.asset_exists(lp_download_path[len(directory)+1:]):
                                    md5 = calculate_md5(lp_download_path)
                                    logger.info(f"{album}: updating {lp_download_path} md5 {md5}")
                                else:
                                    md5 = db.get_asset_md5(lp_download_path[len(directory)+1:])
                                photo_metadata = db.upsert_asset(album, photo, lp_download_path[len(directory)+1:], md5)
                                photo_metadata['file_size'] = os.stat(lp_download_path).st_size
                        if not lp_file_exists:
                            logger.set_tqdm_description(f"{album}: downloading {truncate_middle(lp_download_path[len(directory)+1:], 96)} dated {created_date}")
                            download.download_media(icloud, photo, lp_download_path, lp_size)
                            md5 = calculate_md5(lp_download_path)
                            photo_metadata = db.upsert_asset(album, photo, lp_download_path[len(directory)+1:], md5)
                            photo_metadata['file_size'] = os.stat(lp_download_path).st_size

            return photo_metadata
                    
        amd = {}
        amd['album_name'] = album
        amd['assets'] = []
        photos = icloud.photos.albums[album]
        photos.exception_handler = photos_exception_handler
        photos_count = len(photos)

        # Optional: Only download the x most recent photos.
        if recent is not None:
            photos_count = recent
            photos = itertools.islice(photos, recent)

        tqdm_kwargs = {"total": photos_count}

        if until_found is not None:
            del tqdm_kwargs["total"]
            photos_count = "???"
            # ensure photos iterator doesn't have a known length
            photos = (p for p in photos)

        plural_suffix = "" if photos_count == 1 else "s"
        video_suffix = ""
        if not skip_videos:
            video_suffix = " or video" if photos_count == 1 else " and videos"
        logger.info(f"{album}: processing {photos_count} {size} photo{plural_suffix}{video_suffix}")

        # Use only ASCII characters in progress bar
        tqdm_kwargs["ascii"] = True

        # Skip the one-line progress bar if we're only printing the filenames,
        # or if the progress bar is explicity disabled,
        # or if this is not a terminal (e.g. cron or piping output to file)
        if not os.environ.get("FORCE_TQDM") and (only_print_filenames or no_progress_bar or not sys.stdout.isatty()):
            photos_enumerator = photos
            logger.set_tqdm(None)
        else:
            photos_enumerator = tqdm(photos, **tqdm_kwargs)
            logger.set_tqdm(photos_enumerator)

        consecutive_files_found = 0
        reached_date_since = False

        photos_iterator = iter(photos_enumerator)
        while True:
            try:
                if (until_found is not None and consecutive_files_found >= until_found) or reached_date_since:
                    if reached_date_since:
                        logger.tqdm_write(f"{album}: processed all assets more recent than {date_since}")
                    else:
                        logger.tqdm_write(f"{album}: found {until_found} consecutive previously downloaded photos")
                    break
                photo = next(photos_iterator)
                pmd = download_photo(photo)
                amd['assets'].append(pmd)
            except StopIteration:
                break

        if only_print_filenames:
            sys.exit(constants.ExitCode.EXIT_NORMAL.value)

        if not reached_date_since:
            logger.info(f"{album}: processed all assets")

        if auto_delete:
            autodelete_photos(icloud, folder_structure, directory)

        return amd
            
    cmd = {}
    cmd['icloud_username'] = username
    cmd['directory'] = directory
    cmd['albums'] = []
    if all_albums == True:
        if skip_all_photos:
            logger.info("removing All Photos from the list of albums to process")
            album_titles = [album for album in album_titles if album != "All Photos"]
        if skip_smart_folders:
            logger.info("removing smart folders from the list of albums to process")
            album_titles = [album for album in album_titles if album not in icloud.photos.SMART_FOLDERS.keys()]
    else:
        album_titles = [album]

    logger.info("the following albums will be processed:")
    for album in album_titles:
        logger.info(f"{album}")      

    for album in album_titles:
        amd = download_album(album)
        cmd['albums'].append(amd)

    if create_json_listing:
        json_file_path = directory + "/" + "catalog.json"
        logger.info(f"writing json listing to {json_file_path}")
        with open(json_file_path, "w") as jsonfile:
            jsonfile.write(json.dumps(cmd, indent=4))

    if list_duplicates:
        print_duplicates(db.fetch_duplicates())


    newest_asset = db.newest_asset()
    logger.info(f"Most recent asset in library is {newest_asset['path']} dated {newest_asset['created']}")
    logger.info(f"completed in {datetime.datetime.now() - start}")
