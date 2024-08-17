from django.contrib import admin

# Register your models here.
# admin.py
'''from django.contrib import admin
from .models import APILog

class APILogAdmin(admin.ModelAdmin):
    list_display = ('user', 'method', 'endpoint', 'parameters', 'timestamp')
    list_filter = ('method', 'timestamp', 'user')
    search_fields = ('user__username', 'endpoint', 'parameters')
    readonly_fields = ('user', 'method', 'endpoint', 'parameters', 'timestamp')


admin.site.register(APILog, APILogAdmin)'''
# admin.py
from django.contrib import admin
from .models import APILog

class APILogAdmin(admin.ModelAdmin):
    list_display = ('user', 'method', 'endpoint', 'timestamp')
    search_fields = ('user', 'method', 'endpoint')
    list_filter = ('method', 'timestamp')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'
    readonly_fields = ('user', 'method', 'endpoint', 'parameters', 'timestamp')

admin.site.register(APILog, APILogAdmin)
