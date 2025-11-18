from django.urls import path
from . import views

urlpatterns = [
    path('',views.home,name='home'),
    path('login', views.vulnerable_login, name='login'),
    path('dashboard',views.dashboard,name='login'),
    path('transfer_money',views.transfer_money,name='transfer_money'),
    path('account', views.account_info, name='account'),
    path('api/fetch-external', views.api_fetch_external_data, name='api_fetch_external'),
    
]

