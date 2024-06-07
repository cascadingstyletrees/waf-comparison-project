from colorlog import ColoredFormatter
import urllib.parse
import requests
import logging
import zipfile
import json
import time

from sqlalchemy import MetaData, Table
from tqdm import tqdm

from config import DATA_PATH, LEGITIMATE_URL_PATH, MALICIOUS_URL_PATH, LEGITIMATE_PATH, MALICIOUS_PATH, engine

LOG_LEVEL = logging.DEBUG
LOGFORMAT = "  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s"
logging.root.setLevel(LOG_LEVEL)
formatter = ColoredFormatter(LOGFORMAT)
stream = logging.StreamHandler()
stream.setLevel(LOG_LEVEL)
stream.setFormatter(formatter)
log = logging.getLogger('pythonConfig')
log.setLevel(LOG_LEVEL)
log.addHandler(stream)


def load_data(_log_file):
    """
    Load each data set as json file
    """
    # Load the data
    with open(_log_file) as _file:
        return json.load(_file)


def zip_extract(file_to_extract):
    """
    Extract zip files
    """
    with zipfile.ZipFile(file_to_extract, 'r') as zip_ref:
        zip_ref.extractall(DATA_PATH)


def download_file(url, _progress_bar_name):
    response = requests.get(url, stream=True)

    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True,desc=f"Downloading {_progress_bar_name}")

    file_path = DATA_PATH / url.split("/")[-1]

    # Download the data set in zip format
    with open(file_path, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)

    progress_bar.close()

    # Extract zip data set
    zip_extract(file_path)

def prepare_data():
    if MALICIOUS_PATH.exists():
        log.debug("Malicious Data Set Already Loaded")
    else:
        download_file(MALICIOUS_URL_PATH, "Malicious Data set")
        log.info("Malicious Data Set Preparation Completed.")

    if LEGITIMATE_PATH.exists():
        log.debug("Legitimate Data Set Already Loaded")
    else:
        download_file(LEGITIMATE_URL_PATH, "Legitimate Data set")
        log.info("Legitimate Data Set Preparation Completed.")


def sendRequest(_method, _url, _headers=None, _data=None, _timeout=0.5) -> [int, dict, bool]:
    """
    Send individual request, returns the status code, response headers, and if the request was blocked.
    """
    if _headers and "Host" in _headers:
        _headers.pop("Host")

    attempts = 0
    while attempts < 3:
        try:
            res = requests.request(_method, _url, headers=_headers, data=_data, timeout=_timeout)
            # Check if the response indicates that the request was blocked
            blocked = "The requested URL was rejected. Please consult with your administrator." in res.text or res.status_code == 403
            return [res.status_code, res.headers, blocked]
        except:
            attempts += 1
            time.sleep(0.1 * attempts)

    # If the request fails completely, return a response indicating failure.
    return [0, {}, False]



def isTableExists(_table_name):
    """
    Check if table _table_name exists in the DB.
    """
    with engine.connect() as connection:
        return engine.dialect.has_table(connection, _table_name)


def dropTableIfExists(_table_name):
    metadata = MetaData()
    connection = engine.connect()

    # Check if table exists before dropping
    if engine.dialect.has_table(connection, _table_name):
        table_to_drop = Table(_table_name, metadata, autoload_with=engine)
        table_to_drop.drop(engine)
        log.debug('Starting New test, table waf_comparison was dropped')

    # Remember to close the connection
    connection.close()
