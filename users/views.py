from django.shortcuts import render,redirect
from .forms import SignUpForm,LoginForm,PasswordChangeForm,ResetForms,NewPasswordResetForm
from django.contrib import messages
from .models import User
from django.contrib.auth import  authenticate,login,logout
from django.contrib.auth.decorators import login_required



from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes,force_text

from django.contrib.auth import update_session_auth_hash


import json

def home(request):
    return render(request, 'users/base.html')
def signup(request):

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            save_form = form.save(commit = False)
            save_form.set_password(form.cleaned_data.get('password'))
            save_form.save()
            messages.success(request, 'User registered successfully')
            return redirect('signup')
        else:
            return render(request, 'users/signup.html', {'form':form}) 
    form = SignUpForm()
    return render(request, 'users/signup.html', {'form':form})


def activate_mail(request, uidb64, token):
    try:  
        uid = force_text(urlsafe_base64_decode(uidb64))  
        user = User.objects.get(id=uid)  
        if user is not None: 
            #get the token object
            user.is_verified = True  
            user.save() 
            messages.success(request, 'Email confirmation done successfully')
            return redirect('login')
    except User.DoesNotExist: 
         messages.error(request,"Please sign up") 
         return redirect('signup')


def Login(request):

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(request, username=form.cleaned_data.get('username'), password=form.cleaned_data.get('password'))
            if user is not None:
                if user.is_verified:
                    login(request,user)
                    messages.success(request, 'Login successfully done')
                    return redirect('login')
                else:
                    messages.error(request, 'Please confirm your email')
                    return redirect('login')
            else:
                messages.error(request, "Invalid credentials provided")
                return redirect('login')
    return render(request, 'users/login.html')


def Logout(request):
    logout(request)
    messages.success(request, 'Logout successfully done')
    return redirect('home')

@login_required()
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.POST)
        if form.is_valid():
            user = request.user
            user.set_password(form.cleaned_data.get('new_password'))
            user.save()
            update_session_auth_hash(request, user) #keep user logged in
            messages.success(request, 'Password changed successfully')
            return redirect('login')
        else:
            return render(request, 'users/password_changed.html', {'form':form})

    return render(request, 'users/password_changed.html')


def password_reset_request(request):
    if request.method == "POST":
        form = ResetForms(request.POST)
        if form.is_valid():
            gotten_email = form.cleaned_data.get('email')
            try:
                user = User.objects.get(email=gotten_email)
                if user:
                    subject = "Password Reset Email"
                    email_template_name = "users/password_reset_email.html"
                    c = {
                    "email":user.email,
                    'domain':'loacalhost:8000',
                    'site_name': 'Authy App',
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "user": user,
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'helpraisemyfund@gmail.com' , [user.email], fail_silently=False)
                        return redirect("password_reset_done")
                    except BadHeaderError:
                        messages.error(request, 'please try again')
                        return redirect('reset_password')
                else:
                    messages.error(request, 'The email is not registered')
                    return redirect('reset_password')    
            except User.DoesNotExist:
                messages.error(request, 'The email is not registered')
                return redirect('reset_password')   

    else:
        form = ResetForms()
    return render(request, "users/password_reset_form.html", {"password_reset_form":form})


def password_reset_confirm(request,uidb64,token):
    user_pk = force_text(urlsafe_base64_decode(uidb64))  
    user = User.objects.get(pk=user_pk)
    if request.method == 'POST':
        form = NewPasswordResetForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            user.set_password(password)
            user.save()
            return redirect('password_reset_complete')
        else:
            return render(request, 'users/password_reset_confirm.html', {'form':form}) 
    else:
        form = NewPasswordResetForm()
    return render(request, 'users/password_reset_confirm.html', {'form':form}) 