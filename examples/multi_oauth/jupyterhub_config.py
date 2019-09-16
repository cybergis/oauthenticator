import os
import warnings
import pdb

from oauthenticator.github import GitHubOAuthenticator, GitHubLoginHandler
from oauthenticator.oauth2 import OAuthCallbackHandler
from oauthenticator.google import GoogleOAuthenticator, GoogleOAuthHandler, GoogleLoginHandler
from oauthenticator.hydroshare import HydroShareOAuthenticator,  HydroShareLoginHandler, HydroShareCallbackHandler

class GitHubCallbackHandler(OAuthCallbackHandler):
    pass

class GitHubOAuthenticator_New(GitHubOAuthenticator):
    callback_handler = GitHubCallbackHandler

# launch with docker
c.JupyterHub.spawner_class = 'dockerspawner.DockerSpawner'

# we need the hub to listen on all ips when it is in a container
c.JupyterHub.hub_ip = '0.0.0.0'
# the hostname/ip that should be used to connect to the hub
# this is usually the hub container's name
c.JupyterHub.hub_connect_ip = 'jupyterhub'

# pick a docker image. This should have the same version of jupyterhub
# in it as our Hub.
#c.DockerSpawner.image = 'jupyter/base-notebook'
c.DockerSpawner.image = 'zhiyuli/notebook'

# tell the user containers to connect to our docker network
c.DockerSpawner.network_name = 'jupyterhub'

# delete containers when the stop
c.DockerSpawner.remove = True

c.Application.log_level = 'DEBUG'

c.JupyterHub.authenticator_class = 'oauthenticator.multiauthenticator.MultiOAuthenticator'

c.GitHubOAuthenticator_New.oauth_callback_url = "http://me.domain.com:8000/hub/github/callback"
c.GitHubOAuthenticator_New.client_id = "xxx"
c.GitHubOAuthenticator_New.client_secret = "xxx"

c.GoogleOAuthenticator.oauth_callback_url = "http://me.domain.com:8000/hub/google/callback"
c.GoogleOAuthenticator.client_id = "xxxxx"
c.GoogleOAuthenticator.client_secret = "xxxx"

c.HydroShareOAuthenticator.oauth_callback_url = 'http://me.domain.com:8000/hub/hydroshare/callback'
c.HydroShareOAuthenticator.client_id = 'xxxxx'
c.HydroShareOAuthenticator.client_secret = 'xxxxxx'

c.Authenticator.whitelist = {'github_user1', 'google_user1', 'hydroshare_user1'}
c.Authenticator.admin_users = {'hydroshare_user1'}

c.JupyterHub.template_paths = ['/srv/jupyterhub']

c.MultiOAuthenticator._auth_member_set = set([
    tuple([GitHubOAuthenticator_New, GitHubLoginHandler, GitHubCallbackHandler]),
    tuple([GoogleOAuthenticator, GoogleLoginHandler, GoogleOAuthHandler]),
    tuple([HydroShareOAuthenticator, HydroShareLoginHandler, HydroShareCallbackHandler]),
   ])

## enable authentication state
c.MultiOAuthenticator.enable_auth_state = True
if 'JUPYTERHUB_CRYPT_KEY' not in os.environ:
    warnings.warn(
        "Need JUPYTERHUB_CRYPT_KEY env for persistent auth_state.\n"
        "    export JUPYTERHUB_CRYPT_KEY=$(openssl rand -hex 32)"
    )
    c.CryptKeeper.keys = [ os.urandom(32) ]

pass