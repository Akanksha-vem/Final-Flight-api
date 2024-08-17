FROM python:3.10.9
# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /myproject

RUN pip install --upgrade pip


# Copy requirements.txt and install dependencies
COPY requirements.txt /myproject/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project files
COPY . /myproject/

RUN python manage.py collectstatic --noinput
# Expose port 8001
EXPOSE 8001

ENV django_settings_module=myproject.settings
# Run the Django development server

#CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8001"]
CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8001", "--workers", "3", "--timeout", "200"]
