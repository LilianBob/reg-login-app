from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('register', views.register),
    path('login_after_reg', views.reg_login),
    path('login', views.login),
    path('success', views.success),
    path('logout', views.logout)
]