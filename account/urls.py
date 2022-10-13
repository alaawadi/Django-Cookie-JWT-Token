from django.urls import path
from .views import RegisterView, LoadUserView,RegisterAPI, ChangePasswordView


urlpatterns = [
    path('register', RegisterView.as_view()),
    path('user', LoadUserView.as_view()),
    path('signupapi/',RegisterAPI.as_view()),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),


]
