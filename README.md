**.env File:**

1.We created .env file in the root directory where it stores the amadeus API_KEY and amadeus API_secret_Key to reducing the risk of them being exposed if the code is shared.

2. Add this code in settings.py file.
                 
        import os from dotenv import load_dotenv
   
        load_dotenv()
   
        AMADEUS_API_KEY = os.getenv('AMADEUS_API_KEY') AMADEUS_API_SECRET = os.getenv('AMADEUS_API_SECRET')
        
**simple JWT**:

REST_FRAMEWORK = { 'DEFAULT_AUTHENTICATION_CLASSES': ( 'rest_framework_simplejwt.authentication.JWTAuthentication', ) } 

**MONITORING LOG RECORDS**

1.we created a custom middleware to track all the logs
2.Add the middleware in the settings.py file 'log_rec.middleware.APILogMiddleware', # Custom middleware

**DOCKER FILE**:

1. create a Docker File and docker-compose.yml File. 
2. create a image by using **docker build -t imagename .**
3. Run the container by using **docker run -it -p 8001:8001 imagename:latest**  #use your port number

**Terraform**: 

1.providethis information in .env file
  AWS_REGION=us-east-1, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY 
  
2.AWS configure in the command prompt 

3.Run this commands 
   1.terraform init
   2.terraform apply -target=aws_ecr_repository.my_repo
   3.terraform apply
   
After running the second command Push your image into ECS and then Run the Third command. Then the it automatically deploy the aws resources.

**API Endpoints**:
1. api/register- Register for new user
2. api/login - for authentication and get one time token
3. api/access-token - get access token by using one time token
4. flights/place - get flight details by place
5. flights/date - get flight details by date
6. flights/both - get flight details by both place and date
7. flights/flight-summary - get flight Summary
8. swagger/ - swagger documenatation for above all API endpoints.
ADD **staticfiles** by using command
**python manage.py collectstatic**
Here , I removed dependecies install everything and make use of virtual environment.
