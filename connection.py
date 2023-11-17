"""
MIT License

Copyright (c) [2023] [varsetengineering.com]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

__author__ = "Mizanul H. Chowdhury"
__email__ = "mizanul@mit.edu"

from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter

class SerpensConnectionManager(object):
    """
    Manages HTTP connections for Serpens services.
    """

    def __init__(self, base_url, headers={}, timeout=60, verify=True, proxies=None):
        """
        Initializes SerpensConnectionManager object.

        Args:
            base_url (str): Base URL for the Serpens service.
            headers (dict): Headers to include in requests.
            timeout (int): Timeout for HTTP requests.
            verify (bool): Verify SSL/TLS.
            proxies (dict): Proxy settings for requests.
        """
        self.base_url = base_url
        self.headers = headers
        self.timeout = timeout
        self.verify = verify
        self._s = requests.Session()
        self._s.auth = lambda x: x  # don't let requests add auth headers

        for protocol in ("https://", "http://"):
            adapter = HTTPAdapter(max_retries=1)
            # adds POST to retry whitelist
            allowed_methods = set(adapter.max_retries.allowed_methods)
            allowed_methods.add("POST")
            adapter.max_retries.allowed_methods = frozenset(allowed_methods)

            self._s.mount(protocol, adapter)

        if proxies:
            self._s.proxies.update(proxies)

    def __del__(self):
        """
        Closes the session when the object is deleted.
        """
        if hasattr(self, "_s"):
            self._s.close()

    # Property for base URL
    @property
    def base_url(self):
        return self._base_url

    @base_url.setter
    def base_url(self, value):
        self._base_url = value

    # Property for timeout
    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        self._timeout = value

    # Property for SSL/TLS verification
    @property
    def verify(self):
        return self._verify

    @verify.setter
    def verify(self, value):
        self._verify = value

    # Property for headers
    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, value):
        self._headers = value

    def get_param_headers(self, key):
        """
        Get header value for a specific key.

        Args:
            key (str): Header key.

        Returns:
            str: Header value or None if key is not present.
        """
        return self.headers.get(key)

    def clean_headers(self):
        """
        Clears all headers.
        """
        self.headers = {}

    def has_param_headers(self, key):
        """
        Check if a header key exists.

        Args:
            key (str): Header key.

        Returns:
            bool: True if the key exists, False otherwise.
        """
        return self.get_param_headers(key) is not None

    def set_param_headers(self, key, value):
        """
        Add or update a header.

        Args:
            key (str): Header key.
            value (str): Header value.
        """
        self.headers[key] = value

    def remove_param_headers(self, key):
        """
        Remove a header.

        Args:
            key (str): Header key.
        """
        self.headers.pop(key, None)

    def send_get(self, path, **kwargs):
        """
        Perform a raw HTTP GET request.

        Args:
            path (str): Path for the GET request.
            kwargs: Additional parameters for the request.

        Returns:
            requests.Response: Response object.
        """
        try:
            return self._s.get(
                urljoin(self.base_url, path),
                params=kwargs,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            pass

    def send_post(self, path, data, **kwargs):
        """
        Perform a raw HTTP POST request.

        Args:
            path (str): Path for the POST request.
            data: Data to include in the request.
            kwargs: Additional parameters for the request.

        Returns:
            requests.Response: Response object.
        """
        try:
            return self._s.post(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            pass

    def send_put(self, path, data, **kwargs):
        """
        Perform a raw HTTP PUT request.

        Args:
            path (str): Path for the PUT request.
            data: Data to include in the request.
            kwargs: Additional parameters for the request.

        Returns:
            requests.Response: Response object.
        """
        try:
            return self._s.put(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            pass

    def send_delete(self, path, data=None, **kwargs):
        """
        Perform a raw HTTP DELETE request.

        Args:
            path (str): Path for the DELETE request.
            data: Data to include in the request.
            kwargs: Additional parameters for the request.

        Returns:
            requests.Response: Response object.
        """
        try:
            return self._s.delete(
                urljoin(self.base_url, path),
                params=kwargs,
                data=data or dict(),
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify,
            )
        except Exception as e:
            pass
