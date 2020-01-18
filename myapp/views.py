#!/usr/bin/python
# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
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


def warn(*args, **kwargs):
    pass


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
import csv
from re import sub
from dateutil import parser as dateparser
from time import sleep
from django.http import HttpResponse
from django.shortcuts import render
import os
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.metrics import classification_report
from sklearn.feature_extraction.text import CountVectorizer, \
    TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
import pickle
from sklearn.externals import joblib

import whois
import datetime
sns.set_style('darkgrid', {'axes.facecolor': '.3'})
from youtube_transcript_api import YouTubeTranscriptApi


def result(request):

    try:
        text = request.GET['url']
        aburl = -1
        digits = '0123456789'
        if text[8] in digits:
            oneval = -1
        else:
            oneval = 1
        if len(text) > 170:
            secval = -1
        else:
            secval = 1
        if '@' in text:
            thirdval = -1
        else:
            thirdval = 1
        k = text.count('//')
        if k > 1:
            fourthval = -1
        else:
            fourthval = 1

        if '-' in text:
            fifthval = -1
        else:
            fifthval = 1
        if 'https' in text:
            sixthval = 1
        else:
            sixthval = -1
        temp = text
        temp = temp[6:]
        k1 = temp.count('https')

        if k1 >= 1:
            seventhval = -1
        else:
            seventhval = 1
        if 'about:blank' in text:
            eighthval = -1
        else:
            eighthval = 1
        if 'mail()' or 'mailto:' in text:
            ninthval = -1
        else:
            ninthval = 1
        re = text.count('//')
        if re > 3:
            tenthval = -1
        else:
            tenthval = 1

        import whois
        from datetime import datetime

        url = text

        try:
            res = whois.whois(url)
            try:
                a = res['creation_date'][0]
                b = datetime.now()
                c = b - a
                d = c.days
            except:
                a = res['creation_date']
                b = datetime.now()
                c = b - a
                d = c.days
            if d > 365:
                eleventhval = 1
            else:
                eleventhval = -1
        except:
            aburl = 1
            eleventhval = -1

        if aburl == 1:
            twelthval = -1
        else:
            twelthval = 1

        filename = 'phish_trainedv0.sav'

        loaded_model = joblib.load(filename)

        arg = loaded_model.predict([[
            oneval,
            secval,
            thirdval,
            fourthval,
            fifthval,
            sixthval,
            seventhval,
            eighthval,
            ninthval,
            tenthval,
            eleventhval,
            twelthval,
            ]])
        #print arg[0]
        if arg[0] == 1:
            te = 'Legitimate'
        else:
            te = 'Malicious'
        from json.encoder import JSONEncoder
        final_entity = {'predicted_argument': [int(arg[0])]}

        # directly called encode method of JSON

        #print JSONEncoder().encode(final_entity)
        if arg[0] == 1:
            mal = True
        else:
            mal = False
        obj = Url()
        obj.link = text
        obj.result = te 
        obj.save()
        return render(request, 'result.html',
                  {'result': 'Real-time analysis successfull',
                  'f2': te, 'mal': mal,'text':text})
    except:
        return render(request,'404.html') 

def api(request):
    try:
        text = request.GET['query']
        aburl = -1
        digits = '0123456789'
        if text[8] in digits:
            oneval = -1
        else:
            oneval = 1
        if len(text) > 170:
            secval = -1
        else:
            secval = 1
        if '@' in text:
            thirdval = -1
        else:
            thirdval = 1
        k = text.count('//')
        if k > 1:
            fourthval = -1
        else:
            fourthval = 1

        if '-' in text:
            fifthval = -1
        else:
            fifthval = 1
        if 'https' in text:
            sixthval = 1
        else:
            sixthval = -1
        temp = text
        temp = temp[6:]
        k1 = temp.count('https')

        if k1 >= 1:
            seventhval = -1
        else:
            seventhval = 1
        if 'about:blank' in text:
            eighthval = -1
        else:
            eighthval = 1
        if 'mail()' or 'mailto:' in text:
            ninthval = -1
        else:
            ninthval = 1
        re = text.count('//')
        if re > 3:
            tenthval = -1
        else:
            tenthval = 1

        import whois
        from datetime import datetime

        url = text

        try:
            res = whois.whois(url)
            try:
                a = res['creation_date'][0]
                b = datetime.now()
                c = b - a
                d = c.days
            except:
                a = res['creation_date']
                b = datetime.now()
                c = b - a
                d = c.days
            if d > 365:
                eleventhval = 1
            else:
                eleventhval = -1
        except:
            aburl = 1
            eleventhval = -1

        if aburl == 1:
            twelthval = -1
        else:
            twelthval = 1

        filename = 'phish_trainedv0.sav'

        loaded_model = joblib.load(filename)

        arg = loaded_model.predict([[
            oneval,
            secval,
            thirdval,
            fourthval,
            fifthval,
            sixthval,
            seventhval,
            eighthval,
            ninthval,
            tenthval,
            eleventhval,
            twelthval,
            ]])
        #print arg[0]
        if arg[0] == 1:
            te = 'Legitimate'
        else:
            te = 'Malicious'
        from json.encoder import JSONEncoder
        final_entity = {'predicted_argument': [int(arg[0])]}

        # directly called encode method of JSON

        #print JSONEncoder().encode(final_entity)
        if arg[0] == 1:
            mal = False
        else:
            mal = True
        obj = Url()
        obj.link = text
        obj.result = te 
        obj.save()

        '''return render(request, 'result.html',
                  {'result': 'Real-time analysis successfull',
                  'f2': te, 'mal': mal,'text':text})'''

        import datetime
        mydict = {
            "query" : url,
            "malware" : mal,
            "datetime" : str(datetime.datetime.now())
        }
        return JsonResponse(mydict)
    except:
        return render(request,'404.html')                      

def about(request):
    try:
        return render(request, 'about.html')
    except:
        return render(request,'404.html')

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




			
