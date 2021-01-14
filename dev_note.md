User login and Authentication workflow

OAuth endpoints get mapped to controllers (handlers) at 
```python
    class OAuthenticator(Authenticator):
        login_handler = OAuthLoginHandler
        callback_handler = OAuthCallbackHandler
   
        def get_handlers(self, app):
            return [
                (r'/oauth_login', self.login_handler),
                (r'/oauth_callback', self.callback_handler),
            ]
```

Page hits at GET /oauth_login，code hits at OAuthLoginHandler.get(self),
```python
    class OAuthLoginHandler(OAuth2Mixin, BaseHandler):
        def get(self):
            redirect_uri = self.authenticator.get_callback_url(self)
            extra_params = self.authenticator.extra_authorize_params.copy()
            self.log.info('OAuth redirect: %r', redirect_uri)
            state = self.get_state()
            self.set_state_cookie(state)
            extra_params['state'] = state
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.authenticator.client_id,
                scope=self.authenticator.scope,
                extra_params=extra_params,
                response_type='code',
            )
```

User authenticates against OAuth Provider and redirects back to callback_url at GET /oauth_callback, 
code hits at OAuthCallbackHandler.get(self) and calls OAuthCallbackHandler._login_user_pre_08(self),

```python
    class OAuthCallbackHandler(BaseHandler):
        
        if not hasattr(BaseHandler, 'login_user'):
            # JupyterHub 0.7 doesn't have .login_user
            login_user = _login_user_pre_08
        
        async def get(self):
            self.check_arguments()
            user = await self.login_user()
            if user is None:
                # todo: custom error page?
                raise web.HTTPError(403)
            self.redirect(self.get_next_url(user))

        async def _login_user_pre_08(self):
            """login_user simplifies the login+cookie+auth_state process in JupyterHub 0.8
    
            _login_user_07 is for backward-compatibility with JupyterHub 0.7
            """
            user_info = await self.authenticator.get_authenticated_user(self, None)
            if user_info is None:
                return
            if isinstance(user_info, dict):
                username = user_info['name']
            else:
                username = user_info
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            return user
```

The above OAuthCallbackHandler.authenticator.get_authenticated_user(self, None) starts the following workflow:

- OAuthCallbackHandler.authenticator.get_authenticated_user(self, None) calls subclass oauthenticator.authenticate(), which should return a userdict dict
    - inside subclass oauthenticator.authenticate()
    - it gets a username, saves it in userdict = {"name": username}
    - it may also saves oauth-related info into userdict['auth_state']=XXX (c.Authenticator.enable_auth_state = True with env JUPYTERHUB_CRYPT_KEY set)
    - it returns userdict back to jupyterhub.auth.async def get_authenticated_user(self, handler, data)
- userdict gets renamed to authenticated
- authenticated["username"] gets normalized and updated by subclass oauthenticator.normalize_username()
- authenticated["username"] gets checked by subclass oauthenticator.validate_username(username)
- authenticated["username"] gets checked by subclass oauthenticator.blocked_users
- authenticated["username"] gets checked by subclass oauthenticator.allowed_users
- authenticated (userdict) gets updated by subclass oauthenticator.run_post_auth_hook(handler, authenticated)
- finalized authenticated (userdict) gets returns by jupyterhub.auth.Authenticator.get_authenticated_user(self, handler, data)



-----------------
Spawning
- user login info may be cached
- spawner takes the username and escapes special chars: safe_username
-   spawner can also access to the saved auth_state
- spawner uses safe_username to create user data folder
- spwaner uses safe_username to name single-user notebook container
- if single-user container does not exist, then creates a new one
- and mount user data folder into container
- if container exists, just uses it (be sure to remove old containers if codes related to mount have changed)
