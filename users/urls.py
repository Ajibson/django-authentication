from django.urls import path
from .views import signup,activate_mail,Login,Logout,change_password,password_reset_request,password_reset_confirm,home
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', home, name = 'home'),
    path('register/', signup, name = 'signup'),
    path('login/', Login, name = 'login'),
    path('activate/<uidb64>/<token>/', activate_mail, name = "activate"),
    path('logout/', Logout, name='logout'),
    path('change-password/', change_password, name = 'change-password'),
    path("password_reset/", password_reset_request, name="reset_password"),
    path('reset/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'), name='password_reset_done'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'), name='password_reset_complete'),   
]
