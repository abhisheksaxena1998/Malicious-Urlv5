from django.db import models

# Create your models here.
class UserFeedBack(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    reply = models.TextField()
    replied = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class Url(models.Model):
    link = models.CharField(max_length=10,null=True,default=None)
    result = models.CharField(max_length=100,null=True,default=None)
    add = models.CharField(max_length=1000,null=True,default=None)
    org = models.CharField(max_length=100,null=True,default=None)
    city = models.CharField(max_length=100,null=True,default=None)
    state = models.CharField(max_length=100,null=True,default=None)
    country = models.CharField(max_length=100,null=True,default=None)
    dom = models.CharField(max_length=100,null=True,default=None)
    emails = models.CharField(max_length=100,null=True,default=None)    
    rank = models.IntegerField(null=True,default=None,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
