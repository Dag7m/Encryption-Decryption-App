from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('otp/', views.otp, name='otp'),
    path('aes/', views.aes, name='aes'),
    path('3des/', views.triple_des, name='triple_des'),
    path('rsa/', views.rsa_encryption, name='rsa'),
]

