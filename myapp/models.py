from django.db import models

# Create your models here.
class UserFeedBack(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    reply = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

class Url(models.Model):
    link = models.CharField(max_length=100)
    result = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
