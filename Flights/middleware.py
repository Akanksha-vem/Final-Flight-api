import json
import logging
import jwt
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.contrib.auth.models import User, AnonymousUser
from django.conf import settings
from .models import APILog  # Import the Django APILog model
from .dyanoDB import put_item_api_log  # Import the DynamoDB service function

logger = logging.getLogger('api_logger')

class APILogMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        included_endpoints = [
            '/api/login/',
            '/api/flights/',
            '/api/flights/list/',
            '/flights/'
        ]

        if request.method == 'GET':
            return None

        if not any(request.path.startswith(endpoint) for endpoint in included_endpoints):
            return None

        parameters = {}
        access_token = None
        username = None

        if request.method == 'POST':
            if request.content_type == 'application/json':
                try:
                    request_data = json.loads(request.body)
                    access_token = request_data.get('access', None)
                    username = request_data.get('username', None)
                    parameters = {k: v for k, v in request_data.items() if k != 'access'}
                except json.JSONDecodeError:
                    access_token = None
                    username = None
                    parameters = {}
            else:
                access_token = request.POST.get('access', None)
                username = request.POST.get('username', None)
                parameters = {k: v for k, v in request.POST.items() if k != 'access'}

        if not access_token:
            access_token = request.headers.get('Authorization', None)
            if access_token and access_token.startswith('Bearer '):
                access_token = access_token[7:]

        user = None
        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = None
        elif access_token:
            user_id = self.decode_token(access_token)
            if user_id:
                try:
                    user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    user = None

        # Create log entry using Django's APILog model
        APILog.objects.create(
            user=user if user and not isinstance(user, AnonymousUser) else None,
            method=request.method,
            endpoint=request.path,
            parameters=str(parameters),
            timestamp=timezone.now()
        )

        # Create log entry using DynamoDB
        log_item = {
            'username': user if user else 'None',
            'method': request.method,
            'endpoint': request.path,
            'parameters': str(parameters),
            'timestamp': str(timezone.now())
        }
        put_item_api_log(log_item)  # Store the log in DynamoDB

        if user and not isinstance(user, AnonymousUser):
            logger.info(f'User: {user}, Method: {request.method}, Endpoint: {request.path}, Parameters: {parameters}, Timestamp: {timezone.now()}')
        else:
            logger.info(f'User: None, Method: {request.method}, Endpoint: {request.path}, Parameters: {parameters}, Timestamp: {timezone.now()}')

        return None

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            return payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
