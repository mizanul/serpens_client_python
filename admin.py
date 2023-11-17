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

"""
serpens_openid_connection.py: Manages connections to Serpens OpenID server.
"""

__author__ = "Mizanul H. Chowdhury"
__email__ = "mizanul@mit.edu"

from datetime import datetime, timedelta

from .connection import SerpensConnectionManager
from .exceptions import SerpensPostError
from .serpens_openid import SerpensOpenID

class SerpensOpenIDConnection(SerpensConnectionManager):
    """
    Manages connections to Serpens OpenID server.
    """

    # Class variables for connection parameters
    _server_url = None
    _username = None
    _password = None
    _totp = None
    _realm_name = None
    _client_id = None
    _verify = None
    _client_secret_key = None
    _connection = None
    _custom_headers = None
    _user_realm_name = None
    _expires_at = None
    _serpens_openid = None

    def __init__(
        self,
        server_url,
        username=None,
        password=None,
        token=None,
        totp=None,
        realm_name="master",
        client_id="admin-cli",
        verify=True,
        client_secret_key=None,
        custom_headers=None,
        user_realm_name=None,
        timeout=60,
    ):
        """
        Initializes SerpensOpenIDConnection object.

        Args:
            server_url (str): URL of the Serpens OpenID server.
            username (str): User's username.
            password (str): User's password.
            token (dict): Pre-existing token.
            totp (str): Time-based One-Time Password.
            realm_name (str): Realm name.
            client_id (str): Client ID.
            verify (bool): Verify SSL/TLS.
            client_secret_key (str): Client secret key.
            custom_headers (dict): Custom headers for requests.
            user_realm_name (str): User realm name.
            timeout (int): Timeout for requests.
        """
        # Set default token lifetime fraction
        self.token_lifetime_fraction = 0.9

        # Set connection parameters
        self.server_url = server_url
        self.username = username
        self.password = password
        self.token = token
        self.totp = totp
        self.realm_name = realm_name
        self.client_id = client_id
        self.verify = verify
        self.client_secret_key = client_secret_key
        self.user_realm_name = user_realm_name
        self.timeout = timeout

        # Obtain token if not provided
        if self.token is None:
            self.get_token()

        # Set headers for requests
        self.headers = {
            "Authorization": "Bearer " + self.token.get("access_token"),
            "Content-Type": "application/json",
        } if self.token is not None else {}
        self.custom_headers = custom_headers

        # Initialize ConnectionManager with base URL, headers, and timeout
        super().__init__(
            base_url=self.server_url, headers=self.headers, timeout=60, verify=self.verify
        )

    # Property for server URL
    @property
    def server_url(self):
        return self.base_url

    @server_url.setter
    def server_url(self, value):
        self.base_url = value

    # Property for client ID
    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    # Property for client secret key
    @property
    def client_secret_key(self):
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    # Property for username
    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    # Property for password
    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    # Property for token
    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        self._token = value
        self._expires_at = datetime.now() + timedelta(
            seconds=int(self.token_lifetime_fraction * self.token["expires_in"] if value else 0)
        )

    # Property for expiration time of the token
    @property
    def expires_at(self):
        return self._expires_at

    # Property for SerpensOpenID instance
    @property
    def serpens_openid(self) -> SerpensOpenID:
        if self._serpens_openid is None:
            if self.user_realm_name:
                token_realm_name = self.user_realm_name
            elif self.realm_name:
                token_realm_name = self.realm_name
            else:
                token_realm_name = "master"

            self._serpens_openid = SerpensOpenID(
                server_url=self.server_url,
                client_id=self.client_id,
                realm_name=token_realm_name,
                verify=self.verify,
                client_secret_key=self.client_secret_key,
                timeout=self.timeout,
            )

        return self._serpens_openid

    def get_token(self):
        """
        Obtains a new token based on the specified grant type.
        """
        grant_type = []
        if self.client_secret_key:
            grant_type.append("client_credentials")
        elif self.username and self.password:
            grant_type.append("password")

        if grant_type:
            self.token = self.serpens_openid.token(
                self.username, self.password, grant_type=grant_type, totp=self.totp
            )
        else:
            self.token = None

    def refresh_token(self):
        """
        Refreshes the token if a refresh token is available.
        """
        refresh_token = self.token.get("refresh_token", None) if self.token else None
        if refresh_token is None:
            self.get_token()
        else:
            try:
                self.token = self.serpens_openid.refresh_token(refresh_token)
            except SerpensPostError as e:
                list_errors = [
                    b"Refresh token expired",
                    b"Token is not active",
                    b"Session not active",
                ]
                if e.response_code == 400 and any(err in e.response_body for err in list_errors):
                    self.get_token()
                else:
                    raise

        self.add_param_headers("Authorization", "Bearer " + self.token.get("access_token"))

    def _refresh_if_required(self):
        """
        Refreshes the token if it is required based on expiration time.
        """
        if datetime.now() >= self.expires_at:
            self.refresh_token()

    # Overridden send_get method
    def send_get(self, *args, **kwargs):
        self._refresh_if_required()
        r = super().send_get(*args, **kwargs)
        return r

    # Overridden send_post method
    def send_post(self, *args, **kwargs):
        self._refresh_if_required()
        r = super().send_post(*args, **kwargs)
