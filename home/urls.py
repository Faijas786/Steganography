from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('index', views.index, name="index"),
    path('encryption/', views.encryption_view, name="encryption"),
    path('decryption/', views.decryption_view, name="decryption"),
    path('edit/', views.edit_encryption_view, name='edit_encryption'), 
    path('help/', views.help, name="help"),
    path('contact/', views.contact, name="contact"),
    path('encryption_video/', views.encryption_video_view, name="encryption_video"),
    path('decryption_video/', views.decryption_video_view, name="decryption_video"),
    path('account/', views.account_view, name='account'),
    path('logout/', views.logout_view, name='logout'),
]
  