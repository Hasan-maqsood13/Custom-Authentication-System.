from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from myproject.settings import EMAIL_HOST_USER
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.dateparse import parse_datetime
from django.forms.models import model_to_dict
from django.utils.timezone import make_aware
from django.core.mail import send_mail
from django.utils.text import slugify
from django.core import serializers
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from urllib.parse import unquote
from django.db.models import Sum
from django.urls import reverse
from datetime import timedelta
from datetime import datetime
from .models import *
import random
import json
import re

# Create your views here.
def generate_verification_code(length=8):
    """Generate a random 4-digit numeric code"""
    return str(random.randint(1000, 9999))

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        errors = {}
        
        # Username validation
        if not username:
            errors['name'] = "Name is required."
        elif not re.match(r'^[A-Za-z ]+$', username):
            errors['name'] = "Name can only contain letters and spaces."
        elif User.objects.filter(username=username).exists():
            errors['name'] = "This username is already taken."
        
        # Email validation
        if not email:
            errors['email'] = "Email is required."
        elif User.objects.filter(email=email).exists():
            errors['email'] = "This email is already registered."
        
        # Password validation
        if not password:
            errors['password'] = "Password is required."
        else:
            if len(password) < 8:
                errors['password'] = "Password must be at least 8 characters long."
            elif not re.search(r'[A-Z]', password):
                errors['password'] = "Password must contain at least one uppercase letter."
            elif not re.search(r'[a-z]', password):
                errors['password'] = "Password must contain at least one lowercase letter."
            elif not re.search(r'\d', password):
                errors['password'] = "Password must contain at least one digit."
            elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors['password'] = "Password must contain at least one special character."

        if errors:
            return JsonResponse({'success': False, 'errors': errors})

        try:
            verification_code = generate_verification_code()
            
            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password),
                verification_token=verification_code
            )

            # send_mail(
            #     'Verify Your Email',
            #     f'Hello {user.username},\n\nThank you for registering!\nYour verification code is: {verification_code}',
            #     'hasanmaqsood13@gmail.com', # Yahan apni email daalein
            #     [user.email],
            #     fail_silently=False,
            # )

            next_url = f"/myapp/verify-email/?email={user.email}"
            
            return JsonResponse({'success': True, 'next_url': next_url})

        except Exception as e:
            return JsonResponse({'success': False, 'errors': {'general': str(e)}})
    return render(request, 'signup.html')


def verifyemail(request):
    return render(request, 'verifyemail.html')


def login(request):
    return render(request, 'login.html')


def forgotpassword(request):
    return render(request, 'forgotpassword.html')


def resetpassword(request):
    return render(request, 'resetpassword.html')