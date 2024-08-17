import requests
from .serializers import FlightSummarySerializer,PlaceDateSerializer,DateSerializer,PlaceSerializer
import logging
from datetime import datetime
from rest_framework_simplejwt.tokens import AccessToken
from django.utils import timezone
import pytz  # Import pytz for timezone handling
import certifi
from django.conf import settings
from django.shortcuts import render
from rest_framework import  status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import  AccessToken
from .models import OneTimeToken
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.http import HttpResponse
# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#Home Page
def home(request):
    return HttpResponse("Welcome to the home page!")

#register page
class RegisterView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'password', 'first_name', 'last_name'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username of the user'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user'),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='First name of the user'),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Last name of the user'),
            }
        ),
        responses={
            200: openapi.Response('Success', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )),
        }
    )
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, password=password, first_name=first_name, last_name=last_name)
        user.save()
        return Response({'message': 'User registered successfully'}, status=status.HTTP_200_OK)

def login_page(request):
    return render(request, 'login.html')

#swagger for Login API
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['username', 'password'],
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username of the user'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user'),
        }
    ),
    responses={
        200: openapi.Response('Success', openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'message': openapi.Schema(type=openapi.TYPE_STRING),
                'token': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )),
        400: 'Invalid credentials',
    }
)
#Login API
@api_view(['POST'])
@permission_classes([AllowAny])
def login_api(request):
    username = request.data.get('username')
    password = request.data.get('password')

    # Debug: Print the received username and password
    print(f"Username: {username}, Password: {password}")

    user = authenticate(request, username=username, password=password)
    
    # Debug: Print authentication result
    if user is None:
        # print("Authentication failed for username:", username)
        return Response({'message': 'Authentication failed', 'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Clear previous session username and store new one
    # request.session.flush()  # Clear all session data
    request.session['username'] = username
    # Generate and return one-time token
    OneTimeToken.objects.filter(user=user).delete()
    token = OneTimeToken.objects.create(user=user)
    print('One time token')
    return Response({'message': 'one time token valid for 5 minutes', 'token': str(token.token)}, status=status.HTTP_200_OK)

# swagger for Access-token
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['token'],
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='One-time token'),
        }
    ),
    responses={
        200: openapi.Response('Success', openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'message': openapi.Schema(type=openapi.TYPE_STRING),
                'access': openapi.Schema(type=openapi.TYPE_STRING),
            }
        )),
        400: 'Invalid or expired token',
    }
)
#access-token API
@api_view(['POST'])
@permission_classes([AllowAny])
def access_token(request):
    token = request.data.get('token')
    try:
        one_time_token = OneTimeToken.objects.get(token=token)
    except OneTimeToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Check if the one-time token has expired (valid for 5 minutes)
    if timezone.now() - one_time_token.created_at > timedelta(minutes=5):
        return Response({'error': 'Token expired'}, status=status.HTTP_400_BAD_REQUEST)

    user = one_time_token.user
    access_token = AccessToken.for_user(user)  # Generate access token
    one_time_token.delete()  # Token should be used only once
    return Response({
        'message': 'Access token is valid for 2 hours',
        'access': str(access_token),  # Return access token
    })

#AMADEUS
AMADEUS_BASE_URL = 'https://test.api.amadeus.com'  # Use production URL for live environment
#getting amadeus token
def get_amadeus_access_token():
    url = 'https://test.api.amadeus.com/v1/security/oauth2/token'
    payload = {
        'grant_type': 'client_credentials',
        'client_id': settings.AMADEUS_API_KEY,
        'client_secret': settings.AMADEUS_API_SECRET
    }
    try:
        response = requests.post(url, data=payload, verify=certifi.where())
        response.raise_for_status()
        token = response.json().get('access_token')
        logger.debug(f"Access Token: {token}")
        return token
    except requests.RequestException as e:
        logger.error(f'Error obtaining access token: {str(e)}')
        return None
#get IATA code
def get_iata_code(place, access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    url = f'{AMADEUS_BASE_URL}/v1/reference-data/locations?keyword={place}&subType=AIRPORT'
    try:
        response = requests.get(url, headers=headers, verify=certifi.where())
        response.raise_for_status()
        location_data = response.json()
        if location_data['data']:
            return location_data['data'][0]['iataCode']
    except requests.RequestException as e:
        logger.error(f"Error fetching IATA code: {str(e)}")
    return None
#Get Place name 
def get_place_name(iata_code, access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    url = f'{AMADEUS_BASE_URL}/v1/reference-data/locations?keyword={iata_code}&subType=AIRPORT'
    try:
        response = requests.get(url, headers=headers, verify=certifi.where())
        response.raise_for_status()
        location_data = response.json()
        if location_data['data']:
            airport_info = location_data['data'][0]
            city_name = airport_info.get('address', {}).get('cityName', 'Unknown City')
            return city_name
    except requests.RequestException as e:
        logger.error(f"Error fetching place name: {str(e)}")
    return iata_code  # Return IATA code if city name is not found

#swagger for Flight Summary
@swagger_auto_schema(
    method='post',
    operation_description="Get a summary of flights for given IATA codes",
    request_body=FlightSummarySerializer,
    responses={
        200: openapi.Response(
            description="Successful Response",
            examples={
                "application/json": {
                    "Mumbai": {
                        "place": "Mumbai",
                        "incoming_flights": 10,
                        "outgoing_flights": 15,
                        "total_flights": 25
                    }
                }
            }
        ),
        400: "Bad Request",
        401: "Unauthorized",
        500: "Internal Server Error"
    }
)
#Flight summary API
@api_view(['POST'])
def flight_summary_view(request):
    serializer = FlightSummarySerializer(data=request.data)
    if serializer.is_valid():
        access_token_str = serializer.validated_data['access']
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    try:
        access_token = AccessToken(access_token_str)
    except Exception as e:
        logger.error(f'Error validating access token: {str(e)}')
        return Response({'error': 'Invalid or expired access token'}, status=status.HTTP_401_UNAUTHORIZED)

    token_expiration_time = datetime.fromtimestamp(access_token['exp'], tz=pytz.UTC)

    if timezone.now() > token_expiration_time:
        return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)

    amadeus_access_token = get_amadeus_access_token()
    if not amadeus_access_token:
        return Response({'error': 'Failed to obtain Amadeus access token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    headers = {'Authorization': f'Bearer {amadeus_access_token}'}
    iata_codes = ['BOM', 'DEL', 'PNQ']
    current_date = datetime.now().strftime('%Y-%m-%d')

    result = {}

    for iata_code in iata_codes:
        incoming_flights_count = 0
        outgoing_flights_count = 0

        for code in iata_codes:
            if code != iata_code:
                outgoing_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
                outgoing_params = {
                    'originLocationCode': iata_code,
                    'destinationLocationCode': code,
                    'departureDate': current_date,
                    'adults': 1
                }

                outgoing_response = requests.get(outgoing_endpoint, headers=headers, params=outgoing_params, verify=False)
                if outgoing_response.status_code == 200:
                    outgoing_flight_data = outgoing_response.json()
                    outgoing_flights_count += len(outgoing_flight_data.get('data', []))
                else:
                    logger.error(f"Failed to fetch outgoing flight data: {outgoing_response.json()}")

                incoming_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
                incoming_params = {
                    'destinationLocationCode': iata_code,
                    'originLocationCode': code,
                    'departureDate': current_date,
                    'adults': 1
                }

                incoming_response = requests.get(incoming_endpoint, headers=headers, params=incoming_params, verify=False)
                if incoming_response.status_code == 200:
                    incoming_flight_data = incoming_response.json()
                    incoming_flights_count += len(incoming_flight_data.get('data', []))
                else:
                    logger.error(f"Failed to fetch incoming flight data: {incoming_response.json()}")

        total_flights_count = incoming_flights_count + outgoing_flights_count
        city_name = get_place_name(iata_code, amadeus_access_token)
        result[city_name] = {
            'place': city_name,
            'incoming_flights': incoming_flights_count,
            'outgoing_flights': outgoing_flights_count,
            'total_flights': total_flights_count
        }

    return Response(result)
#swagger for Place
@swagger_auto_schema(
    method='post',
    operation_description="Get of incoming flights and outgoing flight by place",
    request_body=PlaceSerializer,
    responses={
        200: openapi.Response(
            description="Successful Response",
            examples={
                "application/json": {
                    "Mumbai": {
                        "place": "Mumbai",
                        "incoming_flights": 10,
                        "outgoing_flights": 15,
                        "total_flights": 25
                    }
                }
            }
        ),
        400: "Bad Request",
        401: "Unauthorized",
        500: "Internal Server Error"
    }
)

#By place API
@api_view(['POST'])
def flight_place_view(request):
    serializer = PlaceSerializer(data=request.data)
    if serializer.is_valid():
        place = serializer.validated_data['place']
        access_token_str = serializer.validated_data.get('access')  # Access token from the payload
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Validate the access token
    try:
        access_token = AccessToken(access_token_str)
    except Exception as e:
        logger.error(f'Error validating access token: {str(e)}')
        return Response({'error': 'Invalid or expired access token'}, status=status.HTTP_401_UNAUTHORIZED)

    token_expiration_time = datetime.fromtimestamp(access_token['exp'], tz=pytz.UTC)  # Use pytz.UTC here

    if timezone.now() > token_expiration_time:
        return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)

    amadeus_access_token = get_amadeus_access_token()
    if not amadeus_access_token:
        return Response({'error': 'Failed to obtain Amadeus access token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    iata_code = get_iata_code(place, amadeus_access_token)
    if not iata_code:
        return Response({'error': 'Invalid place or IATA code not found'}, status=status.HTTP_400_BAD_REQUEST)

    headers = {'Authorization': f'Bearer {amadeus_access_token}'}
    # Fetch outgoing flights
    iata_codes = ['BOM', 'DEL', 'BLR', 'MAA', 'HYD', 'PNQ', 'AMD', 'GOI', 'COK', 'CCU']
    # current date
    current_date = datetime.now().strftime('%Y-%m-%d')
    incoming_flights_count = 0
    outgoing_flights_count = 0

    for code in iata_codes:
        if code != iata_code:
            # Fetch outgoing flights
            outgoing_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
            outgoing_params = {
                'originLocationCode': iata_code,
                'destinationLocationCode': code,
                'departureDate': current_date,  # Example: Add a date or other required parameters
                'adults': 1  # Example: Add other required parameters
            }

            logger.debug(f"Outgoing Flights Request URL: {outgoing_endpoint}")
            logger.debug(f"Outgoing Flights Headers: {headers}")
            logger.debug(f"Outgoing Flights Params: {outgoing_params}")

            outgoing_response = requests.get(outgoing_endpoint, headers=headers, params=outgoing_params)
            logger.debug(f"Outgoing Flights Response Status Code: {outgoing_response.status_code}")
            logger.debug(f"Outgoing Flights Response Content: {outgoing_response.content}")

            if outgoing_response.status_code == 200:
                outgoing_flight_data = outgoing_response.json()
                outgoing_flights_count += len(outgoing_flight_data.get('data', []))
            else:
                logger.error(f"Failed to fetch outgoing flight data: {outgoing_response.json()}")

            # Fetch incoming flights
            incoming_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
            incoming_params = {
                'destinationLocationCode': iata_code,
                'originLocationCode': code,
                'departureDate': current_date,  # Example: Add a date or other required parameters
                'adults': 1  # Example: Add other required parameters
            }

            logger.debug(f"Incoming Flights Request URL: {incoming_endpoint}")
            logger.debug(f"Incoming Flights Headers: {headers}")
            logger.debug(f"Incoming Flights Params: {incoming_params}")

            incoming_response = requests.get(incoming_endpoint, headers=headers, params=incoming_params)
            logger.debug(f"Incoming Flights Response Status Code: {incoming_response.status_code}")
            logger.debug(f"Incoming Flights Response Content: {incoming_response.content}")

            if incoming_response.status_code == 200:
                incoming_flight_data = incoming_response.json()
                incoming_flights_count += len(incoming_flight_data.get('data', []))
            else:
                logger.error(f"Failed to fetch incoming flight data: {incoming_response.json()}")

    total_flights_count = incoming_flights_count + outgoing_flights_count
    return Response({
        'incoming_flights_count': incoming_flights_count,
        'outgoing_flights_count': outgoing_flights_count,
        'total_flights': total_flights_count
    })
#swagger for Date
@swagger_auto_schema(
    method='post',
    operation_description="Get of incoming flights and outgoing flight by date",
    request_body=DateSerializer,
    responses={
        200: openapi.Response(
            description="Successful Response",
            examples={
                "application/json": {
                    "Mumbai": {
                        "place": "Mumbai",
                        "incoming_flights": 10,
                        "outgoing_flights": 15,
                        "total_flights": 25
                    }
                }
            }
        ),
        400: "Bad Request",
        401: "Unauthorized",
        500: "Internal Server Error"
    }
)
    
# by date API
@api_view(['POST'])
def flight_date_view(request):
    serializer = DateSerializer(data=request.data)
    if serializer.is_valid():
        flight_date = serializer.validated_data['date']
        access_token_str = serializer.validated_data.get('access')  # Access token from the payload
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Validate the access token
    try:
        access_token = AccessToken(access_token_str)
    except Exception as e:
        logger.error(f'Error validating access token: {str(e)}')
        return Response({'error': 'Invalid or expired access token'}, status=status.HTTP_401_UNAUTHORIZED)

    token_expiration_time = datetime.fromtimestamp(access_token['exp'], tz=pytz.UTC)  # Use pytz.UTC here

    if timezone.now() > token_expiration_time:
        return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)

    amadeus_access_token = get_amadeus_access_token()
    if not amadeus_access_token:
        return Response({'error': 'Failed to obtain Amadeus access token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    headers = {'Authorization': f'Bearer {amadeus_access_token}'}
    iata_codes = ['BOM','DEL', 'BLR']
    

    result = {}

    for iata_code in iata_codes:
        incoming_flights_count = 0
        outgoing_flights_count = 0

        for code in iata_codes:
            if code != iata_code:
                # Fetch outgoing flights
                outgoing_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
                outgoing_params = {
                    'originLocationCode': iata_code,
                    'destinationLocationCode': code,
                    'departureDate': flight_date,  # Use provided date
                    'adults': 1  # Example: Add other required parameters
                }

                logger.debug(f"Outgoing Flights Request URL: {outgoing_endpoint}")
                logger.debug(f"Outgoing Flights Headers: {headers}")
                logger.debug(f"Outgoing Flights Params: {outgoing_params}")

                outgoing_response = requests.get(outgoing_endpoint, headers=headers, params=outgoing_params)
                logger.debug(f"Outgoing Flights Response Status Code: {outgoing_response.status_code}")
                logger.debug(f"Outgoing Flights Response Content: {outgoing_response.content}")

                if outgoing_response.status_code == 200:
                    outgoing_flight_data = outgoing_response.json()
                    outgoing_flights_count += len(outgoing_flight_data.get('data', []))
                else:
                    logger.error(f"Failed to fetch outgoing flight data: {outgoing_response.json()}")

                # Fetch incoming flights
                incoming_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
                incoming_params = {
                    'destinationLocationCode': iata_code,
                    'originLocationCode': code,
                    'departureDate': flight_date,  # Use provided date
                    'adults': 1  # Example: Add other required parameters
                }

                logger.debug(f"Incoming Flights Request URL: {incoming_endpoint}")
                logger.debug(f"Incoming Flights Headers: {headers}")
                logger.debug(f"Incoming Flights Params: {incoming_params}")

                incoming_response = requests.get(incoming_endpoint, headers=headers, params=incoming_params)
                logger.debug(f"Incoming Flights Response Status Code: {incoming_response.status_code}")
                logger.debug(f"Incoming Flights Response Content: {incoming_response.content}")

                if incoming_response.status_code == 200:
                    incoming_flight_data = incoming_response.json()
                    incoming_flights_count += len(incoming_flight_data.get('data', []))
                else:
                    logger.error(f"Failed to fetch incoming flight data: {incoming_response.json()}")

        total_flights_count = incoming_flights_count + outgoing_flights_count
        # Fetch place name dynamically
        city_name = get_place_name(iata_code, amadeus_access_token)
        result[city_name] = {
            'place': city_name,
            'incoming_flights': incoming_flights_count,
            'outgoing_flights': outgoing_flights_count,
            'total_flights': total_flights_count
        }
    return Response(result)

#Swagger for BOTH PLACE AND DATE
@swagger_auto_schema(
    method='post',
    operation_description="Get of incoming flights and outgoing flight by place and date",
    request_body=PlaceDateSerializer,
    responses={
        200: openapi.Response(
            description="Successful Response",
            examples={
                "application/json": {
                    "Mumbai": {
                        "place": "Mumbai",
                        "incoming_flights": 10,
                        "outgoing_flights": 15,
                        "total_flights": 25
                    }
                }
            }
        ),
        400: "Bad Request",
        401: "Unauthorized",
        500: "Internal Server Error"
    }
)
#By Both place and date API
@api_view(['POST'])
def flight_both_view(request):
    serializer = PlaceDateSerializer(data=request.data)
    if serializer.is_valid():
        place = serializer.validated_data['place']
        date = serializer.validated_data['date']
        access_token_str = serializer.validated_data.get('access')  # Access token from the payload
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Validate the access token
    try:
        access_token = AccessToken(access_token_str)
    except:
        return Response({'error': 'Invalid or expired access token'}, status=status.HTTP_401_UNAUTHORIZED)
    
    token_expiration_time = datetime.fromtimestamp(access_token['exp'], tz=pytz.UTC)

    if timezone.now() > token_expiration_time:
        return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)

    # Get Amadeus access token
    amadeus_access_token = get_amadeus_access_token()
    if not amadeus_access_token:
        return Response({'error': 'Failed to obtain Amadeus access token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Get IATA code for the place
    iata_code = get_iata_code(place, amadeus_access_token)
    if not iata_code:
        return Response({'error': 'Invalid place or IATA code not found'}, status=status.HTTP_400_BAD_REQUEST)

    headers = {'Authorization': f'Bearer {amadeus_access_token}'}
    iata_codes = ['BOM', 'DEL', 'BLR']

    incoming_flights_count = 0
    outgoing_flights_count = 0

    for code in iata_codes:
        if code != iata_code:
            # Fetch outgoing flights
            outgoing_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
            outgoing_params = {
                'originLocationCode': iata_code,
                'destinationLocationCode': code,
                'departureDate': date,  # Use the provided date
                'adults': 1  # Example: Add other required parameters
            }

            logger.debug(f"Outgoing Flights Request URL: {outgoing_endpoint}")
            logger.debug(f"Outgoing Flights Headers: {headers}")
            logger.debug(f"Outgoing Flights Params: {outgoing_params}")

            outgoing_response = requests.get(outgoing_endpoint, headers=headers, params=outgoing_params)
            logger.debug(f"Outgoing Flights Response Status Code: {outgoing_response.status_code}")
            logger.debug(f"Outgoing Flights Response Content: {outgoing_response.content}")

            if outgoing_response.status_code == 200:
                outgoing_flight_data = outgoing_response.json()
                outgoing_flights_count += len(outgoing_flight_data.get('data', []))
            else:
                logger.error(f"Failed to fetch outgoing flight data: {outgoing_response.json()}")

            # Fetch incoming flights
            incoming_endpoint = f"{AMADEUS_BASE_URL}/v2/shopping/flight-offers"
            incoming_params = {
                'destinationLocationCode': iata_code,
                'originLocationCode': code,
                'departureDate': date,  # Use the provided date
                'adults': 1  # Example: Add other required parameters
            }

            logger.debug(f"Incoming Flights Request URL: {incoming_endpoint}")
            logger.debug(f"Incoming Flights Headers: {headers}")
            logger.debug(f"Incoming Flights Params: {incoming_params}")

            incoming_response = requests.get(incoming_endpoint, headers=headers, params=incoming_params)
            logger.debug(f"Incoming Flights Response Status Code: {incoming_response.status_code}")
            logger.debug(f"Incoming Flights Response Content: {incoming_response.content}")

            if incoming_response.status_code == 200:
                incoming_flight_data = incoming_response.json()
                incoming_flights_count += len(incoming_flight_data.get('data', []))
            else:
                logger.error(f"Failed to fetch incoming flight data: {incoming_response.json()}")

    total_flights_count = incoming_flights_count + outgoing_flights_count

    return Response({
        'incoming_flights': incoming_flights_count,
        'outgoing_flights': outgoing_flights_count,
        'no_of_flights': total_flights_count
    })
