import json

class RiskEngine:
    """
    A class for analyzing and prioritizing security vulnerabilities found by ZAP scanner.

    This engine processes raw scan results, normalizes risk levels, identifies critical endpoints,
    and prioritizes security findings based on their severity and location.

    Attributes:
        raw_results (list): Raw vulnerability data from ZAP scanner
        cwe_to_risk (dict): Mapping of Common Weakness Enumeration (CWE) IDs to risk levels
        critical_endpoints (list): List of URL paths considered critical for the application
    """

    def __init__(self, raw_results):
        """
        Initialize the RiskEngine with raw scan results.

        Args:
            raw_results (list): List of dictionaries containing raw vulnerability data from ZAP
        """
        self.raw_results = raw_results
        self.cwe_to_risk = {
            # Mapping common CWEs to a custom risk score
            'CWE-89': 'High',  # SQL Injection
            'CWE-79': 'Medium', # XSS
            'CWE-200': 'Medium', # Information Exposure
            'CWE-521': 'Low' # Weak Password Requirements
        }
        self.critical_endpoints = ['/login.php', '/admin', '/api/v1/user']

    def parse_results(self):
        """
        Parse and normalize raw ZAP scanner results into a standardized format.

        This method processes each alert from the raw results, normalizing risk levels
        and identifying critical endpoints. It creates a consistent data structure for
        each vulnerability finding.

        Returns:
            list: List of dictionaries containing normalized alert information with fields:
                - alert_name: Name of the vulnerability
                - risk_level: Normalized risk level (High, Medium, Low, Informational)
                - url: The URL where the vulnerability was found
                - cwe_id: Common Weakness Enumeration ID
                - description: Detailed description of the vulnerability
                - is_critical_endpoint: Boolean indicating if vulnerability is on a critical endpoint
                - confidence: ZAP's confidence level in the finding
        """
        parsed_alerts = []
        for alert in self.raw_results:
            risk_level = self.get_normalized_risk(alert)
            is_critical = self.is_critical_endpoint(alert.get('url', ''))
            parsed_alerts.append({
                'alert_name': alert.get('alert', 'N/A'),
                'risk_level': risk_level,
                'url': alert.get('url', 'N/A'),
                'cwe_id': alert.get('cweid', 'N/A'),
                'description': alert.get('description', 'N/A'),
                'is_critical_endpoint': is_critical,
                'confidence': alert.get('confidence', 'N/A')
            })
        return parsed_alerts

    def get_normalized_risk(self, alert):
        """
        Convert ZAP's numeric risk codes to human-readable risk levels.

        Args:
            alert (dict): Raw alert data from ZAP containing a 'riskcode' field

        Returns:
            str: Human-readable risk level ('High', 'Medium', 'Low', or 'Informational')
        """
        zap_risk_code = int(alert.get('riskcode', 0))
        risk_map = {
            3: 'High',
            2: 'Medium',
            1: 'Low',
            0: 'Informational'
        }
        return risk_map.get(zap_risk_code, 'Informational')

    def is_critical_endpoint(self, url):
        """
        Determine if a URL corresponds to a critical endpoint.

        Critical endpoints are sensitive parts of the application that require
        extra attention in security assessment.

        Args:
            url (str): The URL to check

        Returns:
            bool: True if the URL contains a critical endpoint path, False otherwise
        """
        return any(endpoint in url for endpoint in self.critical_endpoints)

    def prioritize_alerts(self, parsed_alerts):
        """
        Sort and prioritize security alerts based on risk level and endpoint criticality.

        This method sorts alerts by their risk level first and then by whether they
        affect critical endpoints. High-risk vulnerabilities on critical endpoints
        will appear first in the results.

        Args:
            parsed_alerts (list): List of parsed and normalized alert dictionaries

        Returns:
            list: Sorted list of alerts in descending order of priority
        """
        prioritized = sorted(
            parsed_alerts,
            key=lambda x: (
                self.get_priority_score(x['risk_level']),
                x['is_critical_endpoint']
            ),
            reverse=True
        )
        return prioritized

    def get_priority_score(self, risk_level):
        """
        Convert risk level strings to numeric scores for sorting.

        Args:
            risk_level (str): Risk level string ('High', 'Medium', 'Low', or 'Informational')

        Returns:
            int: Numeric score (3 for High, 2 for Medium, 1 for Low, 0 for Informational)
        """
        score_map = {'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}
        return score_map.get(risk_level, 0)

# Example Usage:
if __name__ == '__main__':
    # Assume 'raw_zap_results' is the JSON output from zap_scanner.py
    # For this example, we will use a sample alert
    sample_raw_results = [
        {
            'alert': 'SQL Injection',
            'riskcode': 3,
            'url': 'http://dvwa.local/vulnerabilities/sqli/',
            'cweid': '89',
            'description': 'SQL injection...',
            'confidence': 3
        },
        {
            'alert': 'Cross Site Scripting (Persistent)',
            'riskcode': 2,
            'url': 'http://dvwa.local/vulnerabilities/xss_s/',
            'cweid': '79',
            'description': 'Persistent XSS...',
            'confidence': 2
        },
        {
            'alert': 'Information Disclosure - Sensitive data in URL',
            'riskcode': 1,
            'url': 'http://dvwa.local/admin_portal?id=123',
            'cweid': '200',
            'description': 'Information disclosure...'
        },
        {
            'alert': 'X-Frame-Options Header Not Set',
            'riskcode': 1,
            'url': 'http://dvwa.local/login.php',
            'cweid': '693',
            'description': 'X-Frame-Options not set.'
        }
    ]
    risk_engine = RiskEngine(raw_results=sample_raw_results)
    parsed_alerts = risk_engine.parse_results()
    prioritized_alerts = risk_engine.prioritize_alerts(parsed_alerts)

    print("--- Parsed Alerts ---")
    for alert in parsed_alerts:
        print(f"Risk: {alert['risk_level']}, Alert: {alert['alert_name']}, URL: {alert['url']}, Is Critical: {alert['is_critical_endpoint']}")

    print("\n--- Prioritized Alerts (Critical Endpoints and High Risk First) ---")
    for alert in prioritized_alerts:
        print(f"Risk: {alert['risk_level']}, Alert: {alert['alert_name']}, URL: {alert['url']}, Is Critical: {alert['is_critical_endpoint']}")
