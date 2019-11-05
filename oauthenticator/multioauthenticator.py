from urllib.parse import urlsplit

from tornado import gen
from tornado.escape import url_escape
from tornado.httputil import url_concat

from traitlets import (
    Unicode, Integer, Dict, TraitError, List, Bool, Any,
    Type, Set, Instance, Bytes, Float,
    observe, default, Tuple
)

from jupyterhub.auth import Authenticator
from jupyterhub.handlers.login import LoginHandler, LogoutHandler
from jupyterhub.user import User

from oauthenticator.google import GoogleOAuthenticator, GoogleLoginHandler, GoogleOAuthHandler
from oauthenticator.oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator


class MultiLoginHandler(LoginHandler):

    def _render(self, login_error=None):
        """
        Mainly changes the template, also simplify a bit
        """
        oauth_list = []

        for auth_info in self.authenticator._auth_member_set:
            auth_class = auth_info[0]
            auth_obj = auth_class(config=self.config)
            oauth_list.append(str(auth_obj.login_service))

        nextval = self.get_argument('next', default='')
        return self.render_template('login.html',
            next=url_escape(nextval),
            oauth_list=oauth_list,
            login_error=login_error,
            authenticator_login_url=url_concat(
                self.authenticator.login_url(self.hub.base_url),
                {'next': nextval},
            ),
        )

    @gen.coroutine
    def get(self):
        """
        Simplify rendering as there is no username
        """
        self.statsd.incr('login.request')
        if hasattr(self, 'current_user'):
            user = self.current_user
        else:
            user = self.get_current_user()
        if isinstance(user, User):
            # set new login cookie
            # because single-user cookie may have been cleared or incorrect
            self.set_login_cookie(self.get_current_user())
            self.redirect(self.get_next_url(user), permanent=False)
        else:
            self.finish(self._render())

    # legacy codes from https://gist.github.com/danizen/78111676530738fcbca8d8ad87c56690
    # not being used if any OAuthenticator is configured with this MultiOAuthenticator
    @gen.coroutine
    def post(self):
        """
        Redirect to the handler for the appropriate oauth selected
        """
        concat_data = {
            'next': self.get_argument('next', ''),
        }
        if self.authenticator.enable_google and self.get_argument('login_google', None):
            login_url = '{}://{}{}google/login'.format(self.request.protocol, self.request.host, self.hub.base_url)
            self.redirect(url_concat(login_url, concat_data))
        elif self.authenticator.enable_github and self.get_argument('login_github', None):
            login_url = '{}://{}{}github/login'.format(self.request.protocol, self.request.host, self.hub.base_url)
            self.redirect(url_concat(login_url, concat_data))
        else:
            html = self._render(login_error='Unknown or missing authenticator')
            self.finish(html)


class MultiLogoutHandler(LogoutHandler):
    pass


class MultiOAuthenticator(Authenticator):

    _auth_member_set = Set(
                    Tuple(
                        Type(GoogleOAuthenticator, OAuthenticator, help='Must be an OAuthenticator'),
                        Type(GoogleLoginHandler, OAuthLoginHandler, help="Must be a OAuthLoginHandler"),
                        Type(GoogleOAuthHandler, OAuthCallbackHandler, help="Must be a OAuthCallbackHandler")
                        )
    ).tag(config=True)

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        subauth_name = self.__subauth_name
        if subauth_name is None:
            # 2019110 A temporary fix for redirect loop and 500 error
            # see: https://github.com/jupyterhub/jupyterhub/blob/66f29e0f5ab21683fe63186336ae3a6fcf2f5bda/jupyterhub/user.py#L539
            # see: https://github.com/jupyterhub/jupyterhub/issues/2683
            # This is not a Hub bug. Instead, it is a multioauthenticator bug and design issue.
            # If hub server restarts and user opens a browser that still has valid cookies for a already logged in user.
            # In this case Hub will skip authentication process,
            # instead it retrieves saved User object from DB and does spawning with it.
            # the subauth_name here is None because Hub restarted and it only gets saved/cached in memory during a full multioauthentication process
            # Return this function here means No authenticator.pre_spawn_start() will be executed any more
            # A workaround: use spawner.run_pre_spawn_hook()
            # see: https://github.com/jupyterhub/jupyterhub/blob/66f29e0f5ab21683fe63186336ae3a6fcf2f5bda/jupyterhub/user.py#L551
            return
        for auth_tuple in self._auth_member_set:
            auth_class = auth_tuple[0]
            auth_obj = auth_class(config=self.config)
            if auth_obj.login_service.lower() == subauth_name.lower():
                yield auth_obj.pre_spawn_start(user, spawner)
                break

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__client_id = None
        self.__client_secret = None
        self.__scope = None
        self.__subauth_name = None

    @property
    def client_id(self):

        return self.__client_id

    @property
    def client_secret(self):
        return self.__client_secret

    @property
    def scope(self):
        return self.__scope

    def set_oauth_tokens(self, subauth):
        """
        Caches configured information from the subauthenticator in properties
        """

        self.__client_id = subauth.client_id
        self.__client_secret = subauth.client_secret
        self.__scope = subauth.scope
        self.__subauth_name = subauth.login_service

    def get_callback_url(self, handler=None):
        """
        This is called by oauth2, it thinks that there will just be one
        """
        #pdb.set_trace()
        if handler is None:
            raise ValueError("MultiAuthenticator only works with a handler")
        for auth_tuple in self._auth_member_set:
            login_handler_class = auth_tuple[1]
            if type(handler) is login_handler_class:
                auth_obj = auth_tuple[0](config=self.config)
                self.set_oauth_tokens(auth_obj)
                return auth_obj.oauth_callback_url
        return "CALLBACK_URL_NOT_SET"

        return callback_url

    def validate_username(self, username):
        return super().validate_username(username)

    def normalize_username(self, username):
        return super().normalize_username(username)

    def get_handlers(self, app):

        h = [
            ('/login', MultiLoginHandler),
            ('/logout', MultiLogoutHandler),
        ]
        for auth_tuple in self._auth_member_set:

            auth_obj = auth_tuple[0](config=self.config)
            login_service = auth_obj.login_service.lower()
            handlers = dict(auth_obj.get_handlers(app))
            h.extend([
                ('/{}/login'.format(login_service), handlers['/oauth_login']),
                ('/{}/callback'.format(login_service), handlers['/oauth_callback'])
            ])

        return h

    @gen.coroutine
    def authenticate(self, handler, data):
        """
        Delegate authentication to the appropriate authenticator
        """
        for auth_tuple in self._auth_member_set:
            auth_class = auth_tuple[0]
            oauth_handler_class = auth_tuple[2]
            if type(handler) is oauth_handler_class:
                auth_obj = auth_class(config=self.config)
                auth = yield auth_obj.authenticate(handler, data)
                return auth
        return None
