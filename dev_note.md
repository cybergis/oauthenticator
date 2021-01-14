
User login and Authentication workflow
- workflow starts at jupyterhub.auth.Authenticator.get_authenticated_user(self, handler, data)
- call specific subclass oauthenticator.authenticate(), which should return a userdict dict
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
