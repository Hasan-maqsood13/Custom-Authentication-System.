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

            request.session['verification_email'] = email
            request.session['user_id'] = user.id

            next_url = f"/myapp/verify-email/?email={user.email}"

            return JsonResponse({'success': True, 'next_url': next_url})

        except Exception as e:
            return JsonResponse({'success': False, 'errors': {'general': str(e)}})

    return render(request, 'signup.html')


def verifyemail(request):
    if request.method == 'POST':
        dijit1 = request.POST.get('dijit1', '')
        dijit2 = request.POST.get('dijit2', '')
        dijit3 = request.POST.get('dijit3', '')
        dijit4 = request.POST.get('dijit4', '')
        otp = dijit1 + dijit2 + dijit3 + dijit4

        # Check if all digits are provided
        if not all([dijit1, dijit2, dijit3, dijit4]):
            return JsonResponse({'success': False, 'message': 'Please enter all digits.'})

        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'success': False, 'message': "Session expired. Please sign up again."})

        try:
            user = User.objects.get(id=user_id)
            if user.verification_token == otp:
                # Correction 2: Fixed assignment (== to =)
                user.is_verified = True
                user.save()

                # Clean up session
                if 'verification_email' in request.session:
                    del request.session['verification_email']
                if 'user_id' in request.session:
                    del request.session['user_id']

                return JsonResponse({
                    'success': True,
                    'message': 'Email verified successfully!',
                    'redirect_url': '/myapp/'
                })
            else:
                return JsonResponse({'success': False, 'message': 'Invalid verification code.'})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found.'})

    return render(request, 'verifyemail.html')

# Add this view for resending verification codes


def resend_verification(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        if not user_id:
            return JsonResponse({'success': False, 'message': 'Session expired.'})

        try:
            user = User.objects.get(id=user_id)
            new_code = generate_verification_code()
            user.verification_token = new_code
            user.save()

            # In a real application, you would send the email here
            # send_mail(...)

            return JsonResponse({'success': True, 'message': 'New verification code sent.'})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found.'})

    return JsonResponse({'success': False, 'message': 'Invalid request.'})


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(email=email)

            if check_password(password, user.password):
                # Check if user is verified
                if not user.is_verified:
                    return JsonResponse({
                        'success': False,
                        'message': 'Please verify your email before logging in.'
                    })

                # Check if user is active
                if not user.is_active:
                    return JsonResponse({
                        'success': False,
                        'message': 'Your account has been deactivated. Please contact administrator.'
                    })

                # Update last login
                user.last_login = timezone.now()
                user.save()

                # Set session
                request.session['user_id'] = user.id
                request.session['username'] = user.username
                request.session['role'] = user.role

                next_url = "/myapp/dashboard"

                return JsonResponse({'success': True, 'next_url': next_url})
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid username or password.'
                })

        except User.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Invalid username or password.'
            })
    return render(request, 'login.html')


def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            # Generate reset token
            reset_token = generate_verification_code()
            user.verification_token = reset_token
            user.is_verified = False
            user.save()

            # Store email in session for reset page
            request.session['reset_email'] = email
            request.session['user_id'] = user.id

            # In a real application, send email here
            print(f"Password reset code for {email}: {reset_token}")

            next_url = f"/myapp/email-verify/?email={user.email}"

            return JsonResponse({
                'success': True,
                'message': 'Password reset instructions sent to your email.',
                'next_url': next_url,
            })

        except User.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'No account found with this email address.'
            })
    return render(request, 'forgotpassword.html')

def forgotpasswordemailverify(request):
    if request.method == 'POST':
        dijit1 = request.POST.get('dijit1', '')
        dijit2 = request.POST.get('dijit2', '')
        dijit3 = request.POST.get('dijit3', '')
        dijit4 = request.POST.get('dijit4', '')
        otp = dijit1 + dijit2 + dijit3 + dijit4

        # Check if all digits are provided
        if not all([dijit1, dijit2, dijit3, dijit4]):
            return JsonResponse({'success': False, 'message': 'Please enter all digits.'})

        user_email = request.session.get('reset_email')
        if not user_email:
            return JsonResponse({'success': False, 'message': "Session expired. Please sign up again."})

        try:
            user = User.objects.get(email=user_email)
            if user.verification_token == otp:
                # Correction 2: Fixed assignment (== to =)
                user.is_verified = True
                user.save()

                # Clean up session
                if 'reset_email' in request.session:
                    del request.session['reset_email']

                return JsonResponse({
                    'success': True,
                    'message': 'Email verified successfully!',
                    'redirect_url': '/myapp/reset-password/'
                })
            else:
                return JsonResponse({'success': False, 'message': 'Invalid verification code.'})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found.'})
    
    return render(request, 'forgotpasswordemailverify.html')


def resetpassword(request):
    if request.method == 'POST':
        new_password = request.POST.get('newPassword')
        confirm_password = request.POST.get('confirmPassword')

        # User ID session se lo (forgot password ke time store kiya tha)
        user_id = request.session.get('user_id')

        if not user_id:
            return JsonResponse({'success': False, 'message': 'Session expired. Please try again.'})

        if not new_password or not confirm_password:
            return JsonResponse({'success': False, 'message': 'All fields are required.'})

        if new_password != confirm_password:
            return JsonResponse({'success': False, 'message': 'Passwords do not match.'})

        if len(new_password) < 8:
            return JsonResponse({'success': False, 'message': 'Password must be at least 8 characters long.'})

        try:
            user = User.objects.get(id=user_id)
            user.password = make_password(new_password)
            user.save()

            # Reset ho jane ke baad session clear kar do
            del request.session['user_id']
            if 'reset_email' in request.session:
                del request.session['reset_email']

            return JsonResponse({'success': True, 'message': 'Password reset successfully.', 'redirect_url': '/myapp/'})

        except User.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found.'})

    return render(request, 'resetpassword.html')


def dashboard(request):
    return render(request, 'dashboard.html')


def logout(request):
    request.session.flush() 
    return redirect('login')