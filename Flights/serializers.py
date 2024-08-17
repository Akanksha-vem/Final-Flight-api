# flights/serializers.py


from rest_framework import serializers
from django.contrib.auth.models import User
from .models import OneTimeToken
from .models import APILog

#user 
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'first_name', 'last_name']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
#one time token
class OneTimeTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = OneTimeToken
        fields = ['token']

#for flight summary
class FlightSummarySerializer(serializers.Serializer):
        access = serializers.CharField(max_length=255)

# for both place and date
class PlaceDateSerializer(serializers.Serializer):
    place = serializers.CharField(max_length=100)
    date = serializers.DateField()
    access = serializers.CharField(max_length=255)

    
# For Date
class DateSerializer(serializers.Serializer):
    date = serializers.DateField()
    access = serializers.CharField(max_length=255)

#for place
class PlaceSerializer(serializers.Serializer):
    place = serializers.CharField(max_length=100)
    access = serializers.CharField(max_length=255)



#for log records
class APILogSerializer(serializers.ModelSerializer):
    class Meta:
        model = APILog
        fields = '__all__'




