from django.urls import path
from . import views

urlpatterns = [
    path('',views.index,name='index'),
    path('getuserfeedbackform',views.getuserfeedbackform,name="getuserfeedbackform"),
    path('saveuserfeedbackform',views.saveuserfeedbackform,name="saveuserfeedbackform"),
    path('api',views.api,name='api'),
    path('result',views.result,name='result'),
    path('about',views.about,name='about'),
    path('geturlhistory',views.geturlhistory,name="geturlhistory"),
    path('discuss',views.discuss,name="discuss")
]

