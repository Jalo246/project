from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from trackerapp import views  # or however you import your views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('home/', views.home, name='home'),
    path('base/', views.base, name='base'),
    path('', views.login, name='login'),
    path('send_document/', views.send_document, name='send_document'),
    path('track_documents/', views.track_documents, name='track_documents'),
    path('document/<int:document_id>/', views.document_detail, name='document_detail'),
    path('register/', views.register, name='register'),
    path('support/', views.support, name='support'),
    path('statistics/', views.statistics, name='statistics'),
    path('settings/', views.account_settings, name='settings'),
]

if settings.DEBUG:  # Only do this in development!
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
