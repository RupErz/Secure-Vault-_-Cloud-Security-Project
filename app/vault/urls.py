from django.contrib.auth.views import LogoutView
from django.urls import path
from django.views.generic import RedirectView

from . import views

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="file_list", permanent=False)),
    path("healthz", views.healthz),
    path("accounts/login/", views.RateLimitedLoginView.as_view(), name="login"),
    path("accounts/logout/", LogoutView.as_view(), name="logout"),      # POST only
    path("accounts/register/", views.register, name="register"),
    path("files/", views.file_list, name="file_list"),
    path("files/upload/", views.upload, name="file_upload"),
    path("files/<uuid:pk>/", views.file_detail, name="file_detail"),
    path("files/<uuid:pk>/download/", views.download, name="file_download"),
    path("files/<uuid:pk>/delete/", views.delete, name="file_delete"),
    path("activity/", views.activity, name="activity"),
]
