from django.contrib import admin
from .models import User
from .models import Document
# Register your models here.
admin.site.register( User)
admin.site.register(Document)
