from uuid import uuid4
from smtplib import SMTP
from django.conf import settings
from django.contrib.auth.models import User
from hc.accounts.models import Profile


class BasicBackend(object):
    def get_user(self, user_id):
        try:
            q = User.objects.select_related("profile", "profile__current_project")
            return q.get(pk=user_id)
        except User.DoesNotExist:
            return None


class ProfileBackend(BasicBackend):
    def authenticate(self, request=None, username=None, token=None):
        try:
            profiles = Profile.objects.select_related("user")
            profile = profiles.get(user__username=username)
        except Profile.DoesNotExist:
            return None
        if not profile.check_token(token, "login"):
            return None
        return profile.user


class EmailBackend(BasicBackend):
    def authenticate_smtp(self, username, password):
        try:
            with SMTP(host=settings.AUTH_SMTP_HOST, port=settings.AUTH_SMTP_PORT) as s:
                if settings.AUTH_SMTP_STARTTLS:
                    s.starttls()
                s.login(username, password)
                s.noop()
                s.close()
        except Exception:
            return None
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            user = None
        if user is None and settings.AUTH_SMTP_CREATE:
            d = username.split("@")
            if len(d) == 2 and len(d[1]) > 0:
                if d[1].lower() not in settings.AUTH_SMTP_DOMAINS:
                    return None
            user = User.objects.create_user(
                username, email=username, password=str(uuid4())
            )
        return user

    def authenticate(self, request=None, username=None, password=None):
        user = self.authenticate_smtp(username, password)
        if user is not None:
            return user
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return None
        if user.check_password(password):
            return user
