from django.db import models

# Create your models here.
class UserFeedBack(models.Model):
    userid = models.AutoField(primary_key=True)
    title = models.CharField(max_length=100)
    description = models.TextField()
    reply = models.TextField()
    replied = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

class Url(models.Model):
    urlid = models.AutoField(primary_key=True)
    link = models.CharField(max_length=1000,null=True,default="Not Found")
    result = models.CharField(max_length=100,null=True,default="Not Found")
    add = models.CharField(max_length=1000,null=True,default="Not Found")
    org = models.CharField(max_length=100,null=True,default="Not Found")
    city = models.CharField(max_length=100,null=True,default="Not Found")
    state = models.CharField(max_length=100,null=True,default="Not Found")
    country = models.CharField(max_length=100,null=True,default="Not Found")
    dom = models.CharField(max_length=100,null=True,default="Not Found")
    emails = models.CharField(max_length=100,null=True,default="Not Found")    
    rank = models.IntegerField(null=True,default=0,blank=True)
    registrar = models.CharField(max_length=100,null=True,default="Not Found")
    #rank = models.CharField(max_length=100,null=True,default="N A",blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

