#!/usr/bin/python
# -*- coding: utf-8 -*-
def warn(*args, **kwargs):
    pass

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from .models import *


# Create your views here.

def error_404_view(request, exception):
    return render(request,'404.html')

def index(request):
    try:
        return render(request, 'index.html')
    except:
        return render(request, '404.html')


def getuserfeedbackform(request):
    try:
        return render(request, 'userfeedbackform.html')
    except:
        return render(request, '404.html')


def saveuserfeedbackform(request):
    try:
        obj = UserFeedBack()
        obj.title = request.GET['usertitle']
        obj.description = request.GET['userdescription']
        obj.save()
        mydict = {'feedback': True}
        return render(request, 'userfeedbackform.html', context=mydict)
    except:
        return render(request, '404.html')

import warnings
warnings.warn = warn
import warnings
import pandas as pd
import numpy as np
from sklearn.externals import joblib
from lxml import html
from json import dump, loads
from requests import get
import json
from re import sub
from dateutil import parser as dateparser
from time import sleep
from django.http import HttpResponse
from django.shortcuts import render
import os
import pandas as pd
import numpy as np
import pickle
from sklearn.externals import joblib

import whois
import datetime


def result(request):

        """try:"""
        #nm=request.GET['url']
    
        text=request.GET['url']
        
        if text.startswith('https://') or text.startswith('http://'):

            if len(text)<=9:
                return render(request,'errorpage.html')
            aburl=-1
            digits="0123456789"
            if text[8] in digits:
                oneval=-1
            else:
                oneval=1    
            if len(text)>170:
                secval=-1
            else:
                secval=1  
            if "@" in text:
                thirdval=-1
            else:
                thirdval=1    
            k=text.count("//")          
            if k>1:
                fourthval=-1
            else:
                fourthval=1
                
            if "-" in text:
                fifthval=-1
            else:
                fifthval=1         
            if "https" in text:
                sixthval=1
            else:
                sixthval=-1
            temp=text
            temp=temp[6:]
            k1=temp.count("https")

            if k1 >=1:
                seventhval=-1
            else:
                seventhval=1
            if "about:blank" in text:
                eighthval=-1
            else:
                eighthval=1
            if "mail()" or "mailto:" in text:
                ninthval=-1
            else:
                ninthval=1
            re=text.count("//")          
            if re>3:
                tenthval=-1
            else:
                tenthval=1    

            import whois
            from datetime import datetime

            url=text

            try:
                res=whois.whois(url)
                try:
                    a=res['creation_date'][0]
                    b=datetime.now()
                    c=b-a
                    d=c.days
                except:
                    a=res['creation_date']
                    b=datetime.now()
                    c=b-a
                    d=c.days
                if d>365:
                    eleventhval=1
                else:
                    eleventhval=-1
            except:
                aburl=-1
                eleventhval=-1   

            if aburl==-1:
                twelthval=-1
            else:
                twelthval=1 
            import urllib.request, sys, re
            import xmltodict, json

            try:
                xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(text)).read()

                result= xmltodict.parse(xml)

                data = json.dumps(result).replace("@","")
                data_tojson = json.loads(data)
                url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
                rank= int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
                print ("rank",rank)
                if rank<=100000:
                    thirt=1
                else:
                    thirt=-1
                print (thirt)    
            except:
                thirt=-1 
                rank="Not Indexed by Alexa"
                print (rank)                  




            filename = 'phish_trainedv3.sav'

            loaded_model = joblib.load(filename)

            arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval,thirt]]))
            print (arg[0])
            import whois
            url=text
            
            #print (res)
            try:
                res=whois.whois(url)
                name=res["name"]
                print (res["name"])
                org=res['org']
                print (res['org'])
                add=res['address']
                print (res['address'])
                city=res['city']
                print (res['city'])
                state=res['state']
                print (res['state'])
                ziip=res['zipcode']
                print (res['zipcode'])
                country=res['country']
                print (res['country'])
                emails=res["emails"][0]   
                print (res["emails"][0])
                dom=res['domain_name']
                print (res['domain_name'])                
            except:
                name="Not found in database"
                org="Not found in database"
                add="Not found in database"
                city="Not found in database"
                state="Not found in database"
                ziip="Not found in database"
                country="Not found in database"
                emails="Not found in database"
                dom="Not Found"
                

            if dom=="Not Found" and rank=="Not Indexed by Alexa" :
                arg[0]=-1
                #phishing

            if arg[0]==1:
                te="Legitimate"
            else:
                te="Malicious"  
            if arg[0] == 1:
                mal = True
            else:
                mal = False      

            print (name,org,add,city,state,ziip,country,emails,dom)


            from json.encoder import JSONEncoder
            final_entity = { "predicted_argument": [int(arg[0])]}
            # directly called encode method of JSON
            print (JSONEncoder().encode(final_entity)) 
            
            print (dom,rank)
                     
            tags = [name,org,state,add,city,ziip,country,emails,dom,rank]

            tags = list(filter(lambda x: x!="Not Found",tags))
            tags.append(text)
            obj = Url()
            obj.link = text
            obj.add = res['address']
            obj.state = res['state']
            obj.city = res['city']
            #obj.ziip = res['zip_code']
            obj.result = te 
            obj.country = res['country'] 
            obj.emails = res['emails']
            obj.dom = res['domain_name']
            obj.org = res['org']
            obj.rank = rank
            obj.save()
            return render(request,'result.html',{'result':'Real-time analysis successfull','f2':te,'mal': mal,'text':text,'name':name,
                    'org':org,
                    'add':add,
                    'city':city,
                    'state':state,
                    'ziip':ziip,
                    'country':country,'emails':emails,
                    'dom':dom,'rank':rank,"tags":tags})
        else:
            return render(request,'404.html')  
        """except:
        return render(request,'errorpage.html')  """        


def api(request):
    try:
        text=request.GET['query']
        
        if text.startswith('https://') or text.startswith('http://'):

            if len(text)<=9:
                return render(request,'errorpage.html')
            aburl=-1
            digits="0123456789"
            if text[8] in digits:
                oneval=-1
            else:
                oneval=1    
            if len(text)>170:
                secval=-1
            else:
                secval=1  
            if "@" in text:
                thirdval=-1
            else:
                thirdval=1    
            k=text.count("//")          
            if k>1:
                fourthval=-1
            else:
                fourthval=1
                
            if "-" in text:
                fifthval=-1
            else:
                fifthval=1         
            if "https" in text:
                sixthval=1
            else:
                sixthval=-1
            temp=text
            temp=temp[6:]
            k1=temp.count("https")

            if k1 >=1:
                seventhval=-1
            else:
                seventhval=1
            if "about:blank" in text:
                eighthval=-1
            else:
                eighthval=1
            if "mail()" or "mailto:" in text:
                ninthval=-1
            else:
                ninthval=1
            re=text.count("//")          
            if re>3:
                tenthval=-1
            else:
                tenthval=1    

            import whois
            from datetime import datetime

            url=text

            try:
                res=whois.whois(url)
                try:
                    a=res['creation_date'][0]
                    b=datetime.now()
                    c=b-a
                    d=c.days
                except:
                    a=res['creation_date']
                    b=datetime.now()
                    c=b-a
                    d=c.days
                if d>365:
                    eleventhval=1
                else:
                    eleventhval=-1
            except:
                aburl=-1
                eleventhval=-1   

            if aburl==-1:
                twelthval=-1
            else:
                twelthval=1 
            import urllib.request, sys, re
            import xmltodict, json

            try:
                xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(text)).read()

                result= xmltodict.parse(xml)

                data = json.dumps(result).replace("@","")
                data_tojson = json.loads(data)
                url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
                rank= int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
                print ("rank",rank)
                if rank<=100000:
                    thirt=1
                else:
                    thirt=-1
                print (thirt)    
            except:
                thirt=-1 
                rank="Not Indexed by Alexa"
                print (rank)                  




            filename = 'phish_trainedv3.sav'

            loaded_model = joblib.load(filename)

            arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval,thirt]]))
            print (arg[0])
            import whois
            url=text
            
            #print (res)
            try:
                res=whois.whois(url)
                name=res["name"]
                print (res["name"])
                org=res['org']
                print (res['org'])
                add=res['address']
                print (res['address'])
                city=res['city']
                print (res['city'])
                state=res['state']
                print (res['state'])
                ziip=res['zipcode']
                print (res['zipcode'])
                country=res['country']
                print (res['country'])
                emails=res["emails"][0]   
                print (res["emails"][0])
                dom=res['domain_name']
                print (res['domain_name'])                
            except:
                name="Not Found"
                org="Not Found"
                add="Not Found"
                city="Not Found"
                state="Not Found"
                ziip="Not Found"
                country="Not Found"
                emails="Not Found"   
                dom="Not Found"

            if dom=="Not Found" and rank=="Not Indexed by Alexa" :
                arg[0]=-1
                #phishing

            if arg[0]==1:
                te="Legitimate"
            else:
                te="Malicious"  
            if arg[0] == 1:
                mal = True
            else:
                mal = False      
            if arg[0] == 1:
                malstatus = False
            else:
                malstatus = True                 
            from json.encoder import JSONEncoder
            final_entity = { "predicted_argument": [int(arg[0])]}
            # directly called encode method of JSON
            print (JSONEncoder().encode(final_entity)) 
            
            print (dom,rank)
                     
            res=whois.whois(url)
            obj = Url()
            obj.link=res["name"]
            print (res["name"])
            obj.org=res['org']
            print (res['org'])
            obj.add=res['address']
            print (res['address'])
            obj.city=res['city']
            print (res['city'])
            obj.state=res['state']
            print (res['state'])
            print (res['zipcode'])
            obj.country=res['country']
            print (res['country'])
            obj.emails=res["emails"][0]   
            print (res["emails"][0])
            obj.dom=res['domain_name']
            print (res['domain_name'])
            obj.rank = rank
            obj.save()

        '''return render(request, 'result.html',
                  {'result': 'Real-time analysis successfull',
                  'f2': te, 'mal': mal,'text':text})'''

        import datetime
        mydict = {
            "query" : url,
            "malware" : malstatus,
            "datetime" : str(datetime.datetime.now())
        }
        return JsonResponse(mydict)
    except:
        return render(request,'404.html')                      

def about(request):
    #return HttpResponse("about")
    try:
        return render(request, 'about.html')
    except:
        return render(request, 'about.html')
    
def geturlhistory(request):
    try:
        mydict = {
            "urls" : Url.objects.all()
        }
        return render(request,'list.html',context=mydict)
    except:
        return render(request,'404.html')

def discuss(request):
    try:
        mydict = {
            "users" : UserFeedBack.objects.all()
        }
        return render(request,'discuss.html',context=mydict)
    except:
        return render(request,'404.html')

def search(request):
    try:
        query = request.GET['search']
        query = str(query).lower()
        mydict = {
            "urls" : Url.objects.all().filter(Q(link__contains=query) | Q(result__contains=query) | Q(created_at__contains=query))
        }
        return render(request,'list.html',context=mydict)
    except:
        return render(request,'404.html')

def replyform(request,replyid):
    try:
        obj = UserFeedBack.objects.get(id=replyid)
        mydict = {
        "replyid" : obj.id,
        "title" : obj.title,
        "description" : obj.description
        }
        return render(request,'reply.html',context=mydict)
    except:
        return render(request,'404.html')

def savereply(request):
    try:
        print("debug start")
        replyid = request.GET['replyid']
        print(replyid)
        obj = UserFeedBack.objects.get(id=replyid)
        obj.replied = True
        obj.reply = request.GET['userreply']
        obj.save()
        mydict = {
            "reply" : True,
            "users" : UserFeedBack.objects.all()
        }
        print("debug end")
        return render(request,'discuss.html',context=mydict)

    except:
        return render(request,'404.html')

def searchdiscuss(request):
    try:
        query = request.GET['search']
        query = str(query).lower()
        mydict = {
            "users" : UserFeedBack.objects.all().filter(Q(title__contains=query) | Q(description__contains=query) | Q(created_at__contains=query)
            |  Q(replied__contains=query) | Q(reply__contains=query)
            )
        }
        return render(request,'discuss.html',context=mydict)
    except:
        return render(request,'404.html')


			
