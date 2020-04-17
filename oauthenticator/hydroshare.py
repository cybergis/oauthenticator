import os
import warnings
from tornado import gen
import pdb
import json
import base64
import urllib
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from traitlets import Unicode, Dict, Bool
from oauthenticator.generic import GenericOAuthenticator, GenericLoginHandler
from oauthenticator.oauth2 import OAuthCallbackHandler


auth_server_hostname = "www.hydroshare.org"
# "http" or "https"
http_scheme = "https"
auth_server_full_url = "{0}://{1}".format(http_scheme, auth_server_hostname)


class HydroShareCallbackHandler(OAuthCallbackHandler):
    pass

class HydroShareLoginHandler(GenericLoginHandler):
    #_OAUTH_AUTHORIZE_URL = '{0}/o/authorize/'.format(auth_server_full_url)

    # authenticate against CyberGIS-Jupyter for Water Group in HydroShare
    # see https://docs.google.com/document/d/1M3QivDtVFSRCW47EpbzeIcghVp-n0pKC9IBWsOyVyhk/edit#
    # Group on HydroShare: https://www.hydroshare.org/group/157
    _OAUTH_AUTHORIZE_URL = '{0}/o/groupauthorize/157/'.format(auth_server_full_url)
    pass

class HydroShareOAuthenticator(GenericOAuthenticator):

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL',
                       '{0}/hsapi/userInfo/'.format(auth_server_full_url)),
        config=True,
        help="Userdata url to get user data login information"
    )
    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL',
                       '{0}/o/token/'.format(auth_server_full_url)),
        config=True,
        help="Access token endpoint URL"
    )

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )

    login_service = Unicode(
        "HydroShare",
        config=True
    )

    callback_handler = HydroShareCallbackHandler
    login_handler = HydroShareLoginHandler

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):

        auth_state = yield user.get_auth_state()
        import pprint
        pprint.pprint("-------------OAuth Token------------")

        # What HS wants
        # {'access_token': 'XXXXXXXXXXX',
        # 'token_type': 'Bearer',
        # 'expires_in': 2592000,
        # 'refresh_token': 'XXXXXXXXXXXXXXX',
        # 'scope': 'read write'}
        pprint.pprint(auth_state)
        if not auth_state:
            # user has no auth state
            return
        # # define some environment variables from auth_state

        auth = (auth_state, self.client_id)
        spawner.environment['HS_AUTH'] = json.dumps(auth)

    async def authenticate(self, handler, data=None):

        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub"
        }

        if self.basic_auth:
            b64key = base64.b64encode(
                bytes(
                    "{}:{}".format(self.client_id, self.client_secret),
                    "utf8"
                )
            )
            headers.update({"Authorization": "Basic {}".format(b64key.decode("utf8"))})

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )

        resp = await http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        scope = resp_json.get('scope', '')

        ## For HydroShare OAuth Start
        # if (isinstance(scope, str)):
        #     scope = scope.split(' ')

        expires_in = resp_json.get('expires_in', None)
        token_type = resp_json.get('token_type', None)
        ## For HydroShare OAuth End

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        if self.userdata_token_method == "url":
            url = url_concat(self.userdata_url, dict(access_token=access_token))

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return

        ## For HydroShare OAuth Start
        return_dict = {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }

        if expires_in is not None:
            return_dict['auth_state']['expires_in'] = expires_in
        if token_type is not None:
            return_dict['auth_state']['token_type'] = token_type

        return return_dict