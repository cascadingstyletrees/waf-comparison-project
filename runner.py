# Import required libraries
from sqlalchemy.exc import ObjectNotExecutableError
import concurrent.futures
from tqdm import tqdm
import pandas as pd
import datetime
import socket
import json

from analyzer import analyze_results
# Import custom modules
from config import engine, WAFS_DICT, DATA_PATH
from helper import load_data, sendRequest, log, prepare_data, dropTableIfExists


def check_engine_connection():
    """
    Function to check if a successful connection to the database engine can be established.
    """
    try:
        # Try executing a simple query to check the connection
        _ = pd.read_sql_query("SELECT 1", engine)
        log.info("Database Connected Successfully")

    except ObjectNotExecutableError:
        raise ObjectNotExecutableError("Connection to the database failed")


class Wafs:
    """
    Class for handling all WAF related operations.
    """

    # Initialization of the WAFS class, setting up the Web Application Firewall (WAF) data structure and data frame.
    def __init__(self):
        self.wafs = WAFS_DICT
        self.inverse_waf_dict = {v: k for k, v in self.wafs.items()}
        # self.df = pd.DataFrame(WAFS_DICT)

    def get_url_by_waf_name(self, key):
        """
        Function to retrieve the WAF URL by its name.
        """
        return self.wafs[key]

    def get_waf_name_by_url(self, key):
        """
        Function to retrieve the WAF name by its URL
        """
        return self.inverse_waf_dict[key]

    def check_connection(self):
        checkFailed = False
        log.debug("Initiating health check to confirm proper connectivity configurations.")
        for _waf in self.wafs:
            # Unpacking the new three-element list returned by sendRequest
            resStatusCode, isBlocked, resHeaders = sendRequest(
                'GET',
                self.get_url_by_waf_name(_waf),
                {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"}
            )

            if resStatusCode == 200:
                log.info(f"Health check passed - WAF: {_waf:50}")
            else:
                log.error(f"Health check failed - WAF: {_waf:50}")
                checkFailed = True

        # For each WAF, send a potentially harmful GET request and check if it gets blocked.
        log.debug("Initiating WAF functionality verification to ensure that the WAF is in prevention mode and is capable of blocking malicious requests.")
        for _waf in self.wafs:
            # Again, unpack the response to include headers
            resStatusCode, isBlocked, resHeaders = sendRequest('GET', self.get_url_by_waf_name(_waf) + "/<script>alert(1)</script>")
            if isBlocked:
                log.info(f"WAF functionality check passed - WAF: {_waf:50}")
            else:
                log.error(f"WAF functionality check failed - WAF: {_waf:50}")
                checkFailed = True

        # If any test has failed, raise an error. Otherwise, log that all tests have completed successfully.
        if checkFailed:
            raise ConnectionError(
                "One or more tests have failed. Please review your configurations and initiate the test again.")
        else:
            log.debug("All tests have been successfully completed.")

    
    def _send_payloads(self, _data, _url, _test_name):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as _executor:
            res = list(
                tqdm(
                    _executor.map(
                        lambda payload: sendRequest(
                            payload['method'],
                            _url + payload['url'],
                            payload['headers'],
                            payload['data']
                        ),
                        _data
                    ),
                    position=3, leave=False, total=len(_data)
                )
            )

        # Creating a DataFrame from the data
        dff = pd.DataFrame(_data)

        # Unpacking response tuple and adding them as separate columns in the DataFrame
        dff[['response_status_code', 'response_headers', 'isBlocked']] = pd.DataFrame(res, index=dff.index)

        # JSON dumping the headers for a consistent storage format
        dff['response_headers'] = dff['response_headers'].apply(lambda headers: json.dumps(dict(headers)))

        # Additional DataFrame modifications
        dff['machineName'] = socket.gethostname()
        dff['DestinationURL'] = _url
        dff['WAF_Name'] = self.get_waf_name_by_url(_url)
        dff['DateTime'] = datetime.datetime.now()
        dff['TestName'] = _test_name.stem
        dff['dataset'] = _test_name.parent.stem
        dff['headers'] = dff['headers'].apply(json.dumps)  # Ensure headers are stored as a JSON string

        # Clean up problematic characters in URL and data fields
        dff['url'] = dff['url'].str.replace("\x00", "\uFFFD")
        dff['data'] = dff['data'].str.replace("\x00", "\uFFFD")

        # Upload the DataFrame to the Database
        dff.to_sql('waf_comparison', engine, if_exists='append', index=False)


    def send_payloads(self):
        """
        Function to send payloads to all WAFs
        """
        if not self.wafs.values():
            log.warning('WAFS_DICT is empty, skipping payload send step.')
            return

        # Delete old results:
        

        for test_name in tqdm(list(DATA_PATH.rglob('*json')), desc="Sending requests", position=1, leave=False):

            data = load_data(test_name)
            for url in tqdm(self.wafs.values(), position=2, leave=False):
                self._send_payloads(data, url, test_name)


def main():
    """
    Main function to execute the WAF testing process
    """
    wafs = Wafs()
    dropTableIfExists('waf_comparison')
    wafs.check_connection()
    check_engine_connection()
    prepare_data()
    wafs.send_payloads()


if __name__ == '__main__':
    main()
