"""
Allow to use UIUC channel and Github channel through CILogon
single-user jupyter container name: UIUC -- uillinois_<netid>
                                    github -- <username>
allowed users:  UIUC --- all users
                github ---  username list defined in DB


Tested with oauthenticator 0.12.3 and 6f239bebecbb3fb0242de7f753ae1c93ed101340
            jupyterhub 1.3


# The following should be in environment

CILOGON_CLIENT_ID=XXXX
CILOGON_CLIENT_SECRET=XXXXX
OAUTH_CALLBACK_URL=https://XXXXXX/hub/oauth_callback


# The following should be in jupyter_config.py

from oauthenticator.cilogon_cybergis import CILogonOAuthenticator_CyberGIS

c.JupyterHub.authenticator_class = CILogonOAuthenticator_New
_cilogon_idp_list = [
    # the first idp is selected by default on CILogon UI
    # value of idp and value of idp_name should match what CILogon returns
    # short_name: is used as a readable label referenced in this code only
    #             github should be "github"
    # uanme_key: which key:value pair CILogon returns to be used as username in this code; 
    #            uiuc should use "eppn", which returns uiuc email address XXXXX@illinois.edu, only XXXXX will be used in username
    #            github should use "oidc", which returns github user id (numbers), will be converted into github login username
    #            None or Not Set: not recommended; will use original username_claim and/or additional_username_claims as the key
    # prefix/suffix: append to username (ex: <prefix_>username<_suffix>)
    #                None or Not Set -- treat as empty string ""
    # cilogon_allowed_users: * -- any username is allow; 
    #                        [XXX, XXX] - only listed username(s) allowed; 
    #                        None or Not Set - use original allowed_users settings
    
    {"idp": "urn:mace:incommon:uiuc.edu", "idp_name": "University of Illinois at Urbana-Champaign",
     "short_name": "uillinios", "uname_key": "eppn", "prefix": "uillinois_", "cilogon_allowed_users": "*"},
    {"idp": "http://github.com/login/oauth/authorize", "idp_name": "GitHub", "short_name": "github",
     "uname_key": "oidc"},
]
_cilogon_idp_dict = dict(zip([i["idp"] for i in _cilogon_idp_list], _cilogon_idp_list))
c.CILogonOAuthenticator_CyberGIS.cilogon_idp_dict = _cilogon_idp_dict
# this will be added to authenticate_url as querystring to display selected idps in cilogon ui
c.Authenticator.idp = ",".join([i["idp"] for i in _cilogon_idp_list])

"""


import json
from tornado import web
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from traitlets import Dict
from oauthenticator.cilogon import CILogonOAuthenticator


class CILogonOAuthenticator_CyberGIS(CILogonOAuthenticator):

    cilogon_idp_dict = Dict(dict(), config=True)
    cilogon_idp_used = None
    cilogon_idp_used_info = None

    async def authenticate(self, handler, data=None):

        """We set up auth_state based on additional CILogon info if we
        receive it.
        """
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a CILogon Access Token
        # See: http://www.cilogon.org/oidc
        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.oauth_callback_url,
            code=code,
            grant_type='authorization_code',
        )

        url = url_concat(self.token_url, params)

        req = HTTPRequest(url, headers=headers, method="POST", body='')

        resp = await http_client.fetch(req)
        token_response = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = token_response['access_token']
        self.log.info("Access token acquired.")
        # Determine who the logged in user is
        params = dict(access_token=access_token)
        req = HTTPRequest(
            url_concat("https://%s/oauth2/userinfo" % self.cilogon_host, params),
            headers=headers,
        )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        self.log.info(resp_json)

        # check if idp used is in provided idp list
        idp = resp_json.get("idp")
        self.cilogon_idp_used = idp
        if self.cilogon_idp_dict.get(idp) is None:
            self.log.error(
                "Trying to login from a idp not in cilogon_idp_dict: %s", idp
            )
            raise web.HTTPError(500, "Trying to login from a idp not expected")
        else:
            self.cilogon_idp_used_info = self.cilogon_idp_dict.get(idp)

        uname_key = self.cilogon_idp_used_info.get("uname_key")
        if uname_key is not None:
            username = resp_json.get(uname_key)
        else:
            claimlist = [self.username_claim]
            if self.additional_username_claims:
                claimlist.extend(self.additional_username_claims)

            self.log.info("Get username from key: {}".format(claimlist))

            for claim in claimlist:
                username = resp_json.get(claim)
                if username:
                    break
            if not username:
                if len(claimlist) < 2:
                    self.log.error(
                        "Username claim %s not found in response: %s",
                        self.username_claim,
                        sorted(resp_json.keys()),
                    )
                else:
                    self.log.error(
                        "No username claim from %r in response: %s",
                        claimlist,
                        sorted(resp_json.keys()),
                    )
                raise web.HTTPError(500, "Failed to get username from CILogon")

        # Convert github user id (oidc) to login username
        if self.cilogon_idp_used_info["short_name"].lower() == "github":
            req = HTTPRequest(
                "https://api.github.com/user/{}".format(username)
            )
            resp = await http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))
            username = resp_json["login"]

        # remove @ from username
        if "@" in username:
            username = username.split('@')[0]

        # append string to username
        username = "{}{}{}".format(self.cilogon_idp_dict[idp].get("prefix", ''),
                                   username,
                                   self.cilogon_idp_dict[idp].get("suffix", ''))
        ## not being used
        # if self.allowed_idps:
        #     gotten_name, gotten_idp = username.split('@')
        #     if gotten_idp not in self.allowed_idps:
        #         self.log.error(
        #             "Trying to login from not allowed domain %s", gotten_idp
        #         )
        #         raise web.HTTPError(500, "Trying to login from a domain not allowed")
        #     if len(self.allowed_idps) == 1 and self.strip_idp_domain:
        #         username = gotten_name
        userdict = {"name": username}
        # Now we set up auth_state
        userdict["auth_state"] = auth_state = {}
        # Save the token response and full CILogon reply in auth state
        # These can be used for user provisioning
        #  in the Lab/Notebook environment.
        auth_state['token_response'] = token_response
        # store the whole user model in auth_state.cilogon_user
        # keep access_token as well, in case anyone was relying on it
        auth_state['access_token'] = access_token
        auth_state['cilogon_user'] = resp_json
        return userdict

    # jupyterhub/jupyterhub/auth.py
    def check_allowed(self, username, authentication=None):
        """Check if a username is allowed to authenticate based on configuration

        Return True if username is allowed, False otherwise.
        No allowed_users set means any username is allowed.

        Names are normalized *before* being checked against the allowed set.

        .. versionchanged:: 1.0
            Signature updated to accept authentication data and any future changes

        .. versionchanged:: 1.2
            Renamed check_whitelist to check_allowed
        """
        cilogon_allowed_users = self.cilogon_idp_used_info.get("cilogon_allowed_users")
        if cilogon_allowed_users is not None:
            self.log.warning("Checking username {} against cilogon_allowed_users".format(username))
            if cilogon_allowed_users == "*":
                return True
            elif type(cilogon_allowed_users) is list:
                return username in cilogon_allowed_users
        else:
            self.log.warning("Checking username {} against allowed_users".format(username))

        if not self.allowed_users:
            # No allowed set means any name is allowed
            return True
        return username in self.allowed_users