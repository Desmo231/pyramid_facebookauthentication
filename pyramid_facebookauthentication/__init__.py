# package

import base64, hashlib, hmac, json, urllib, urlparse, time

from zope.interface import implements
from pyramid.interfaces import IAuthenticationPolicy, IDebugLogger
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.request import add_global_response_headers
from pyramid.response import Response
from pyramid.security import (
    Authenticated,
    Everyone,
    )

class FacebookAuthenticationPolicy(CallbackAuthenticationPolicy):
    """ An object representing Facebook Pyramid authentication policy. """
    implements(IAuthenticationPolicy)
    def __init__(self, app_id, app_secret, app_url, app_permissions='user_about_me', callback=None):
        self.fbuser = FacebookAuthHelper(app_id, app_secret, app_url, app_permissions, callback)
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

    def effective_principals(self, request):
        return self.fbuser.effective_principals(request)

    def login_view(self, context, request, redir_url=None, scope=None):
        return self.fbuser.login_view(request, redir_url, scope)



class FacebookAuthHelper(object):

    def __init__(self, app_id, app_secret, app_url, app_permissions='user_about_me', callback=None):
        self.app_id = app_id
        self.app_secret = app_secret
        self.app_url = app_url
        self.app_permissions = app_permissions
        self.callback = callback
        self.debug = False

    def identify(self, request):
        identity = {'uid':None, 'access_token':None}
        sr = self._key_from_request(request, 'signed_request')
        if sr: # Get the user from a signed_request
            if not self.check_signed_request(sr):
                return None
            user = self.get_user_from_signed_request(sr)
            if not user:
                return None
            identity['uid'] = user.get('user_id')
            identity['access_token'] = user.get('oauth_token')
            identity['signed_request'] = sr
            if 'signed_request' not in request.cookies or request.cookies.get('signed_request') != sr:
                add_global_response_headers(request, self.remember(request, identity['uid'], sr))

        elif "fbs_" + self.app_id in request.cookies:
            # Try to get the user from fb cookie.
            user = self.get_user_from_cookie(request.cookies)
            if not user:
                return None
            identity['uid'] = user.get('uid')
            identity['access_token'] = user.get('access_token')
        else:
            # look for access_token
            access_token = self._key_from_request(request, 'access_token')
            identity = self.get_identity_via_access_token(access_token)
            if 'signed_request' in identity:
                add_global_response_headers(request, self.remember(request, identity['uid'], identity['signed_request']))

        return identity

    def login_view(self, request, redir_url, scope):
        url = redir_url or self.app_url
        if not scope:
            scope = self.app_permissions
        return Response("<script type='text/javascript'>top.location.href = 'https://www.facebook.com/dialog/oauth?client_id={0}&redirect_uri={1}&type=user_agent&display=page&scope={2}';</script>".format(self.app_id, urllib.quote(url + request.path_info + '?' + request.query_string), scope))

    def _key_from_request(self, request, key):
        if key in request.params:
            return request.params.get(key)
        if key in request.cookies:
            return request.cookies.get(key)
        return None

    def remember(self, request, uid, signed_request=None):
        if not signed_request: return []
        return [
            ('P3P', 'CP="HONK"'),
            ('Set-Cookie', 'signed_request="{0}"; Path=/'.format(signed_request))
            ]

    def forget(self, request):
        return []

    def effective_principals(self, request):
        """ Copied straight out of pyramid 1.3.2 authorization.py. Only
        change was to move user None check to after groups to allow for anonymous
        users in a group """
        effective_principals = [Everyone]
        identity = self.identify(request)
        userid = identity and identity['uid'] or None
        debug = self.debug
        if self.callback is None:
            debug and self._log(
                'groupfinder callback is None, so groups is []',
                'effective_principals',
                request)
            groups = []
        else:
            groups = self.callback(userid, request)
            debug and self._log(
                'groupfinder callback returned %r as groups' % (groups,),
                'effective_principals',
                request)
        if groups is None:  # is None!
            debug and self._log(
                'returning effective principals: %r' % (
                    effective_principals,),
                'effective_principals',
                request
                )
            return effective_principals
        effective_principals.extend(groups)

        if userid is None:
            debug and self._log(
                'unauthenticated_userid returned %r; returning %r' % (
                    userid, effective_principals),
                'effective_principals',
                request
                )
            return effective_principals

        effective_principals.append(Authenticated)
        effective_principals.append(userid)

        debug and self._log(
            'returning effective principals: %r' % (
                effective_principals,),
            'effective_principals',
            request
             )
        return effective_principals

    def _log(self, msg, methodname, request):
        logger = request.registry.queryUtility(IDebugLogger)
        if logger:
            cls = self.__class__
            classname = cls.__module__ + '.' + cls.__name__
            methodname = classname + '.' + methodname
            logger.debug(methodname + ': ' + msg)

    """ Borrowed from https://github.com/facebook/python-sdk
    """

    def get_user_from_cookie(self, cookies):
        cookie = cookies.get("fbs_" + self.app_id, "")
        if not cookie: return None
        args = dict((k, v[-1]) for k, v in urlparse.parse_qs(cookie.strip('"')).items())
        payload = "".join(k + "=" + args[k] for k in sorted(args.keys())
                      if k != "sig")
        sig = hashlib.md5(payload + self.app_secret).hexdigest()
        expires = int(args["expires"])
        if sig == args.get("sig") and (expires == 0 or time.time() < expires):
            return args
        else:
            return None

    """ https://github.com/facebook/runwithfriends/blob/master/main.py
    """
    def get_user_from_signed_request(self, signed_request):
        """Parse the signed_request parameter from Facebook canvas applications.
        """
        sig, payload = signed_request.split(u'.', 1)
        return json.loads(self.base64_url_decode(payload))

    def check_signed_request(self, signed_request):
        sig, payload = signed_request.split(u'.', 1)
        sig = self.base64_url_decode(sig)
        return sig == self.sign(payload)

    def get_identity_via_access_token(self, access_token):
        identity = {'uid':None, 'access_token':None}
        if not access_token: return identity
        try:
            userdat = json.load(urllib.urlopen('https://graph.facebook.com/me?access_token='+access_token))
        except:
            return identity
        user = dict([(key, userdat.get(key)) for key in ['username', 'first_name', 'last_name', 'verified', 'name', 'locale', 'updated_time', 'languages', 'link', 'location', 'gender', 'timezone', 'id']])
        user['signed_request'] = self.make_signed_request(access_token,user)
        user['access_token'] = access_token
        user['uid'] = user.get('id')
        return user

    def sign(self, payload):
        return hmac.new(
            self.app_secret, msg=payload, digestmod=hashlib.sha256).digest()

    def base64_url_decode(self, data):
        data = data.encode(u'ascii')
        data += '=' * (4 - (len(data) % 4))
        return base64.urlsafe_b64decode(data)

    def make_signed_request(self, access_token, user):
        # {"country":"us","locale":"en_US","age":{"min":21}},
        payload = {"algorithm":"HMAC-SHA256", "expires":0,
          "issued_at":int(time.time()),
          "oauth_token":access_token,
          "user_id":user['id'],
          "user": user}
        data = base64.urlsafe_b64encode(json.dumps(payload))
        sig = base64.urlsafe_b64encode(self.sign(data))
        return sig + "." + data

