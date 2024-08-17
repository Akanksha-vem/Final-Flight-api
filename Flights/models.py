from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from django import forms

# API log records
class APILog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    method = models.CharField(max_length=10)
    endpoint = models.CharField(max_length=255)
    parameters = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user} {self.method} {self.endpoint} {self.timestamp}"

#One Time token 
class OneTimeToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.token)
    class Meta:
        db_table = 'flights_onetimetoken'
#user registeration
class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'password', 'first_name', 'last_name']



