from pyramid.config import Configurator
from pyramid.response import Response 
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.exceptions import Forbidden
from pyramid.security import Authenticated, Allow
from paste.httpserver import serve

from facebookauthentication import FacebookAuthenticationPolicy

def hello_world(request): return Response('Hello world!')

class RootFactory(object):
    __acl__ = [ (Allow, Authenticated, 'view') ]

    def __init__(self, request): pass

if __name__ == '__main__': 

    app_id = None # Facebook application id
    app_secret = None # Facebook application secret
    app_url = None # Facebook app url http://apps.facebook.com/APP
    app_perms = 'user_about_me' # http://developers.facebook.com/docs/authentication/permissions/
    authentication_policy=FacebookAuthenticationPolicy(app_id, app_secret, app_url, app_perms)
    authorization_policy = ACLAuthorizationPolicy()
    config = Configurator(
        authentication_policy=authentication_policy, 
        authorization_policy=authorization_policy,
        root_factory=RootFactory
        )
    config.add_view(hello_world, permission='view') 
    config.add_view(authentication_policy.login_view, context=Forbidden)
    app = config.make_wsgi_app()
    serve(app, host='0.0.0.0', port=80)

