from django.db import models
from django.utils import timezone
from django.utils.text import slugify
from django.db.models import CharField, DateField, DecimalField, ImageField
import uuid

# Create your models here.
class User(models.Model):
    # Neccessary Info
    username = models.CharField(max_length=33, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

    # Verification 
    verification_token = models.CharField(max_length=255, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    
    # Account Management
    Role_choices = (
        ('admin', 'Admin'),
        ('employee', 'Employee'),
    )
    role = models.CharField(max_length=10, choices=Role_choices, default='employee')
    is_active = models.BooleanField(default=True)

    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)
    last_updated = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.username} - {self.email} - {self.role}"