from logging import getLogger, StreamHandler, Formatter, Handler, NOTSET, getLevelName
from datetime import datetime
import sqlite3 as sql
import os, sys
import traceback

# Need to adapt inside sqlite3 to make timestamps without .mmmmmm work
def adapt_datetime(val):
    return val.isoformat(" ", "microseconds")

def setup_database(directory):
    DatabaseHandler.db_file = directory + "/icloudpd.db"
    sql.register_adapter(datetime, adapt_datetime)

class DatabaseHandler(Handler):
    is_pruned = False

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(DatabaseHandler, cls).__new__(cls)
            cls.instance.db_conn = sql.connect(DatabaseHandler.db_file, detect_types=sql.PARSE_DECLTYPES | sql.PARSE_COLNAMES)
            cls.instance.db_conn.row_factory = sql.Row
            cls.instance._createLogTable()
            cls.instance._createPhotoAssetTable()
            cls.instance._pruneLogTable()
        return cls.instance
    
    def __init__(self):
        super().__init__()

    def _pruneLogTable(self):
        try:
            sql = "DELETE from Log"
            self.db_conn.execute(sql)
            self.db_conn.commit()
            self.db_conn.execute("VACUUM")
        except sql.Error as er:
            self.print_error(er)

    def _createLogTable(self):
        try:
            self.db_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS Log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    asctime TIMESTAMP,
                    filename TEXT,
                    funcName TEXT,
                    levelname TEXT,
                    levelno INTEGER,
                    lineno INTEGER,
                    message TEXT,
                    module TEXT,
                    msecs FLOAT,
                    name TEXT,
                    pathname TEXT,
                    process INTEGER
                    )
                """
                )
            self.db_conn.commit()

        except sql.Error as er:
            self.print_error(er)

    def _createPhotoAssetTable(self):
        try:
            self.db_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS PhotoAsset (
                    id TEXT,
                    filename TEXT,
                    size TEXT,
                    created TIMESTAMP,
                    asset_date TIMESTAMP,
                    added_date TIMESTAMP,
                    dimensionX INTEGER,
                    dimensionY INTEGER,
                    item_type TEXT,
                    item_type_extension TEXT,
                    path TEXT PRIMARY KEY,
                    md5 TEXT,
                    album
                    )
                """
                )
            self.db_conn.commit()
            self.db_conn.execute("create index if not exists IX_PA_MD5 on PhotoAsset (md5)")
            self.db_conn.commit()
        except sql.Error as er:
            self.print_error(er)

    def print_error(self, er):
        print('SQLite error: %s' % (' '.join(er.args)))
        print("Exception class is: ", er.__class__)
        print('SQLite traceback: ')
        exc_type, exc_value, exc_tb = sys.exc_info()
        print(traceback.format_exception(exc_type, exc_value, exc_tb))

    def newest_asset(self):
        try:
            return self.db_conn.execute("SELECT path, created FROM PhotoAsset ORDER BY created DESC LIMIT 1").fetchone()
        except sql.Error as er:
            self.print_error(er)

    def asset_exists(self, path):
        try:
            row = self.db_conn.execute("select path from PhotoAsset where path = ?", (path,)).fetchone()
            return row is not None
        except sql.Error as er:
            self.print_error(er)

    def upsert_asset(self, album, photo, path, md5):
        try:
            self.db_conn.execute("INSERT OR REPLACE INTO PhotoAsset VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13)", (
                photo.id,
                photo.filename,
                photo.size,
                photo.created,
                photo.asset_date,
                photo.added_date,
                photo.dimensions[0],
                photo.dimensions[1],
                photo.item_type,
                photo.item_type_extension,
                path,
                md5,
                album
                )
            )
            self.db_conn.commit()
        except sql.Error as er:
            self.print_error(er)

    def fetch_duplicates(self):
        try:
            return self.db_conn.execute("select A.md5, A.path, B.count from PhotoAsset A join (select md5, path, count(*) as count from PhotoAsset group by md5 having count(md5) > 1) B on A.md5 = B.md5 order by count, A.md5").fetchall()
        except sql.Error as er:
            self.print_error(er)

    def emit(self, record):
        try:
            self.db_conn.execute("INSERT INTO Log (timestamp, asctime, filename, funcName, levelname, levelno, lineno, message, module, msecs, name, pathname, process) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                datetime.now(),
                record.asctime,
                record.filename,
                record.funcName,
                record.levelname,
                record.levelno,
                record.lineno,
                record.message,
                record.module,
                record.msecs,
                record.name,
                record.pathname,
                record.process
                )
            )
            self.db_conn.commit()
        except sql.Error as er:
            self.print_error(er)
