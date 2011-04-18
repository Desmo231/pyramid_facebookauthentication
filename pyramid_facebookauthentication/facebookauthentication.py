import facebook
from zope.interface import implements
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.request import add_global_response_headers
from pyramid.response import Response 

class FacebookAuthenticationPolicy(CallbackAuthenticationPolicy):
    """ An object representing Facebook Pyramid authentication policy. """
    implements(IAuthenticationPolicy)
    def __init__(self, app_id, app_secret, app_url, app_permissions=None, callback=None):
        self.fbuser = FacebookAuthHelper(app_id, app_secret, app_url, app_permissions)
        self.callback = callback

    def unauthenticated_userid(self, request):
        result = self.fbuser.identify(request)
        if result:
            return result['uid']

    def remember(self, request, principal, **kw):
        """ Accepts the following kw args: ``max_age``."""
        return self.fbuser.remember(request, principal, **kw)

    def forget(self, request):
        return self.fbuser.forget(request)

    def login_view(self, context, request):
        return self.fbuser.login_view(request)

class FacebookAuthHelper(object):

    def __init__(self, app_id, app_secret, app_url, app_permissions='user_about_me'):
        self.app_id = app_id
        self.app_secret = app_secret
        self.app_url = app_url
        self.app_permissions = app_permissions

    def identify(self, request):
        identity = {'uid':None, 'access_token':None}
        sr = self._signed_request(request)
        if sr: # Get the user from a signed_request
            if not facebook.check_signed_request(sr, self.app_secret):
                return None
            user = facebook.get_user_from_signed_request(sr)
            if not user:
                return None
            identity['uid'] = user.get('user_id')
            identity['access_token'] = user.get('oath_token')
            identity['signed_request'] = sr
            if 'signed_request' not in request.cookies or request.cookies.get('signed_request') != sr:
                add_global_response_headers(request, self.remember(request, identity['uid'], sr))
            
        else: # Try to get the user from fb cookie.
            user = facebook.get_user_from_cookie(
                request.cookies,
                self.app_id,
                self.app_secret)
            if not user:
                return None
            identity['uid'] = user.get('uid')
            identity['access_token'] = user.get('access_token')

        return identity

    def login_view(self, request):
        return Response("<script type='text/javascript'>top.location.href = 'https://www.facebook.com/dialog/oauth?client_id={0}&redirect_uri={1}&type=user_agent&display=page&scope={2}';</script>".format(self.app_id, self.app_url, self.app_permissions))

    def _signed_request(self, request):
        if 'signed_request' in request.params:
            return request.params.get('signed_request')
        if 'signed_request' in request.cookies:
            return request.cookies.get('signed_request')
      

    def remember(self, request, uid, signed_request=None):
        if not signed_request: return []
        return [
            ('Set-Cookie', 'fb_uid="{0}"; Path=/'.format(uid)),
            ('Set-Cookie', 'signed_request="{0}"; Path=/'.format(signed_request))
            ]

    def forget(self, request):
        return []

