from django.urls import path
from user_input import views

urlpatterns = [
    path('', views.get_user_input, name='form'),
    path('results/', views.display_result, name='result'),
]