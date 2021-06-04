from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
import re
import bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

#create your views here

def index(request):
    return render(request, 'index.html')

def register(request):
    if request.method == "GET":
        return redirect('/')
    if request.method == "POST":
        errors = User.objects.registration_val(request.POST)
        # if len(errors) > 0:
        #     for key, val in errors.items():
        #         messages.error(request, val)
        # return redirect("/")
        if errors:
            for e in errors.values():
                messages.error(request, e)
            return redirect('/')
        else:
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            email = request.POST['email']
            password = request.POST['password']
            hash_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user= User.objects.create(first_name=first_name, last_name=last_name, email=email, password=hash_pw)
            request.session['user_id'] = new_user.id
            messages.success(request, "You have successfully registered!")
            # return redirect('/success')

            # messages.success(request, 'successfully registered. Login to proceed!')
            return render(request, "login.html")
        
def reg_login(request):
    if request.method == "GET":
        return redirect('/')
    if request.method == "POST":
            email = request.POST['email']
            password = request.POST['password']
            if not User.objects.authenticate(email, password):
                messages.error(request, 'Email and Password do not match!')
                return redirect("/login_after_reg")
            else:
                user = User.objects.get(email=email)
                request.session['user_id'] = user.id
                return redirect("/success")

def login(request):
    if request.method == "GET":
        return redirect('/')
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        if not User.objects.authenticate(email, password):
            messages.error(request, 'Email and Password do not match!')
            return redirect("/login_after_reg")
        else:
            user = User.objects.get(email=email)
            request.session['user_id'] = user.id
            return redirect("/success")

def success(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        context = {
        "user": user
        }
        return render(request, 'success.html', context)
    else: 
        messages.error(request, 'You must be logged in order to access the shows')
    return redirect("/login_after_reg")

def logout(request):
    del request.session['user_id']
    return redirect("/login_after_reg")