import requests
import time
import logging
import os

logger = logging.getLogger(__name__)

class ZAPScanner:
    """
    A class to manage OWASP ZAP security scanning operations.

    This class provides an interface to interact with a ZAP instance running in a Docker container,
    allowing for automated security scanning of web applications through both passive and active scans.

    Attributes:
        target_url (str): The URL of the web application to be scanned
        api_key (str): The API key for authenticating with ZAP
        zap_host (str): The hostname where ZAP is running
        zap_port (str): The port number where ZAP is listening
        zap_base_url (str): The complete base URL for the ZAP API
    """

    def __init__(self, target_url, api_key=None):
        """
        Initialize the ZAP scanner with target URL and configuration.

        Args:
            target_url (str): The URL of the web application to scan
            api_key (str, optional): The API key for ZAP authentication. Defaults to None.
        """
        self.target_url = target_url
        # Use the fixed API key from docker-compose or environment
        self.api_key = api_key or "zap-api-key-12345"
        # Get ZAP host and port from environment variables
        self.zap_host = os.environ.get('ZAP_HOST', 'localhost')
        self.zap_port = os.environ.get('ZAP_PORT', '8080')
        self.zap_base_url = f'http://{self.zap_host}:{self.zap_port}'

    def start_zap_container(self):
        """Check if ZAP is ready - no need to start container as it's managed by docker-compose."""
        try:
            logger.info(f"Checking ZAP readiness at {self.zap_base_url}")
            self._wait_for_zap_ready()
            logger.info("ZAP is ready for scanning")
        except Exception as e:
            logger.error(f"ZAP is not available: {e}")
            raise Exception("ZAP service is not available. Please ensure docker-compose is running.")

    def _wait_for_zap_ready(self, max_wait=60):
        """
        Wait for the ZAP service to become available and ready for API calls.

        Args:
            max_wait (int, optional): Maximum time to wait in seconds. Defaults to 60.

        Raises:
            Exception: If ZAP service doesn't respond within the max_wait time.
        """
        wait_time = 0
        logger.info(f"Waiting for ZAP to be ready at {self.zap_base_url} (max {max_wait}s)...")

        while wait_time < max_wait:
            try:
                logger.info(f"Attempting to connect to ZAP (attempt {wait_time//5 + 1})")
                response = requests.get(
                    f'{self.zap_base_url}/JSON/core/view/version/',
                    params={'apikey': self.api_key},
                    timeout=10
                )
                if response.status_code == 200:
                    version_info = response.json()
                    logger.info(f"ZAP is ready! Version: {version_info.get('version', 'Unknown')}")
                    return
                else:
                    logger.warning(f"ZAP responded with status {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.info(f"ZAP not ready yet: {e}")

            time.sleep(5)
            wait_time += 5
            logger.info(f"Waiting for ZAP to be ready... ({wait_time}s/{max_wait}s)")

        logger.error(f"ZAP service failed to respond within {max_wait} seconds.")
        raise Exception(f"ZAP service failed to respond within the expected time of {max_wait} seconds.")

    def run_passive_scan(self):
        """
        Execute a passive scan using ZAP's spider functionality.

        This method initiates a spider scan of the target URL, which crawls the web application
        and passively collects security-relevant information without actively testing for vulnerabilities.

        Raises:
            Exception: If the spider scan fails to start or complete.
        """
        try:
            logger.info("Starting passive scan (spider)...")

            # Start spider scan
            spider_url = f'{self.zap_base_url}/JSON/spider/action/scan/'
            response = requests.get(spider_url, params={
                'url': self.target_url,
                'apikey': self.api_key
            })

            if response.status_code != 200:
                raise Exception(f"Failed to start spider: {response.text}")

            spider_id = response.json()['scan']
            logger.info(f"Spider started with ID: {spider_id}")

            # Poll for spider completion
            while True:
                status_url = f'{self.zap_base_url}/JSON/spider/view/status/'
                response = requests.get(status_url, params={
                    'scanId': spider_id,
                    'apikey': self.api_key
                })

                if response.status_code == 200:
                    status = int(response.json()['status'])
                    logger.info(f"Spider progress: {status}%")
                    if status >= 100:
                        break

                time.sleep(5)

            logger.info("Passive scan complete.")

        except Exception as e:
            logger.error(f"Error during passive scan: {e}")
            raise

    def run_active_scan(self):
        """
        Execute an active scan against the target URL.

        This method performs active security testing by sending potentially malicious requests
        to the target application to identify security vulnerabilities. It monitors the scan
        progress and provides detailed logging of the scanning process.

        Raises:
            Exception: If the active scan fails to start or complete.
        """
        try:
            logger.info("Starting active scan...")

            # Start active scan
            ascan_url = f'{self.zap_base_url}/JSON/ascan/action/scan/'
            response = requests.get(ascan_url, params={
                'url': self.target_url,
                'apikey': self.api_key
            })

            if response.status_code != 200:
                raise Exception(f"Failed to start active scan: {response.text}")

            scan_id = response.json()['scan']
            logger.info(f"Active scan started with ID: {scan_id}")

            # Poll for active scan completion with enhanced status reporting
            last_status = -1
            last_rule = None
            while True:
                status_url = f'{self.zap_base_url}/JSON/ascan/view/status/'
                response = requests.get(status_url, params={
                    'scanId': scan_id,
                    'apikey': self.api_key
                })

                if response.status_code == 200:
                    status = int(response.json()['status'])

                    # Get current scanning rule and phase
                    current_rule = None
                    try:
                        rules_url = f'{self.zap_base_url}/JSON/ascan/view/scanProgress/'
                        rules_response = requests.get(rules_url, params={
                            'scanId': scan_id,
                            'apikey': self.api_key
                        })
                        if rules_response.status_code == 200:
                            progress_data = rules_response.json()
                            if 'scanProgress' in progress_data and progress_data['scanProgress']:
                                host_progress = progress_data['scanProgress'][-1]['HostProcess']
                                if host_progress:
                                    plugin_data = host_progress[-1]['plugin']
                                    current_rule = plugin_data['name']
                                    if current_rule != last_rule:
                                        status_msg = f"Currently scanning with rule: {current_rule}"
                                        logger.info(status_msg)
                                        last_rule = current_rule
                    except Exception as e:
                        logger.debug(f"Could not get detailed scan progress: {e}")

                    # Only log if progress has changed or we have a new rule
                    if status != last_status:
                        progress_msg = f"Active scan progress: {status}%"
                        if current_rule:
                            progress_msg += f" (Current rule: {current_rule})"
                        logger.info(progress_msg)
                        last_status = status

                    if status >= 100:
                        logger.info("Active scan phase complete")
                        break

                time.sleep(2)  # Reduced polling interval for more responsive updates

            logger.info("Active scan complete.")

        except Exception as e:
            logger.error(f"Error during active scan: {e}")
            raise

    def get_results(self):
        """
        Retrieve the security scan results from ZAP.

        Returns:
            list: A list of dictionaries containing alert details. Each dictionary represents
                  a security finding with information about the vulnerability type, risk level,
                  and affected URL.

        Raises:
            Exception: If unable to retrieve results from the ZAP API.
        """
        try:
            logger.info("Retrieving scan results...")

            alerts_url = f'{self.zap_base_url}/JSON/core/view/alerts/'
            response = requests.get(alerts_url, params={
                'baseurl': self.target_url,
                'apikey': self.api_key
            })

            if response.status_code == 200:
                results = response.json()['alerts']
                logger.info(f"Retrieved {len(results)} alerts from scan.")
                return results
            else:
                raise Exception(f"Failed to get results: {response.text}")

        except Exception as e:
            logger.error(f"Error retrieving results: {e}")
            return []

    def stop_zap_container(self):
        """
        Clean up the ZAP session after scanning.

        This method creates a new session in ZAP to clear any existing session data,
        ensuring a clean state for subsequent scans. The actual ZAP container is managed
        by docker-compose and is not stopped by this method.
        """
        try:
            logger.info("Cleaning up scan session...")
            # Clear ZAP session data for next scan
            clear_url = f'{self.zap_base_url}/JSON/core/action/newSession/'
            response = requests.get(clear_url, params={
                'name': f'session_{int(time.time())}',
                'apikey': self.api_key
            })
            if response.status_code == 200:
                logger.info("ZAP session cleared successfully")
            else:
                logger.warning(f"Failed to clear ZAP session: {response.status_code}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# Example Usage:
if __name__ == '__main__':
    TARGET = 'http://testphp.vulnweb.com'

    scanner = ZAPScanner(target_url=TARGET)
    try:
        scanner.start_zap_container()
        scanner.run_passive_scan()
        scanner.run_active_scan()
        results = scanner.get_results()
        print(f"Found {len(results)} vulnerabilities.")
    except Exception as e:
        print(f"Scan failed: {e}")
    finally:
        scanner.stop_zap_container()
