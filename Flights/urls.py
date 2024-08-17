
'''from django.urls import path


from .views import flight_both_view,flight_date_view,flight_summary_view,flight_place_view
 
urlpatterns = [
     path('both/', flight_both_view, name='flight-both'),
    path('place/', flight_place_view,name='place'),
    path('date/', flight_date_view, name='date'),
     path('flight-summary/', flight_summary_view, name='By date and place')
]'''
from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .views import flight_both_view,flight_date_view,flight_summary_view,flight_place_view
from django.urls import path
from .views import RegisterView,login_api, access_token,home
from django.conf import settings
from django.conf.urls.static import static 

schema_view = get_schema_view(
   openapi.Info(
      title="Flight API",
      default_version='v1',
      description="API documentation for Flight Finder",
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
   path('', home, name='home'),
   path('register/', RegisterView.as_view(), name='register-page'),
   path('api/login/', login_api, name='login_api'),
   path('api/access-token/', access_token, name='access-token'),
   path('flight-summary/', flight_summary_view, name='By date and place'),
   path('flights/both/', flight_both_view, name='flight-both'),
   path('flights/place/', flight_place_view,name='place'),
   path('flights/date/', flight_date_view, name='date'),
   path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   #path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

]
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

