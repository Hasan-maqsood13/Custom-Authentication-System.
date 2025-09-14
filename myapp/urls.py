from django.contrib import admin
from django.urls import path
from myapp import views

urlpatterns = [
    path('', views.login, name="login"),
    path('signup/', views.signup, name="signup"),
    path('verify-email/', views.verifyemail, name="verifyemail"),
    path('resend-verification/', views.resend_verification, name='resend_verification'),
    path('forgot-password/', views.forgotpassword, name="forgotpassword"),
    path('reset-password/', views.resetpassword, name="resetpassword"),
]
