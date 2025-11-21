from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("vulnerable-login", views.vulnerable_sql_login, name="vulnerable_login"),
    path("regular-login", views.regular_login, name="regular_login"),
    path("dashboard", views.dashboard, name="dashboard"),
    path("transfer", views.transfer_money, name="transfer"),
    path("account", views.account_info, name="account"),
<<<<<<< HEAD
    path('ssrf', views.ssrf_page, name='ssrf'),
    path('fetch-url', views.fetch_url, name='fetch_url'),
    path('internal/mock', views.internal_mock, name='internal_mock'),

    path("logout", views.logout_view, name="logout"),

=======
    path("api/fetch-external", views.api_fetch_external_data, name="api_fetch_external"),
    path("logout", views.logout_view, name="logout"),
>>>>>>> c6510aa97ca8c40f67333f07e61e9f82816ac7b1
]