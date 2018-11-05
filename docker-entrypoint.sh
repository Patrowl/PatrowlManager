#!/bin/bash

source env/bin/activate

# Collect static files
echo "[+] Collect static files"
python manage.py collectstatic --noinput

# Apply database migrations
echo "[+] Make database migrations"
python manage.py makemigrations

# Apply database migrations
echo "[+] Apply database migrations"
python manage.py migrate

# Create the default admin user
echo "[+] Create the default admin user"
echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@dev.patrowl.io', 'Bonjour1!')" | python manage.py shell

# Populate the db with default data
echo "[+] Populate the db with default data"
python manage.py loaddata var/data/assets.AssetCategory.json
python manage.py loaddata var/data/engines.Engine.json
python manage.py loaddata var/data/engines.EnginePolicyScope.json
python manage.py loaddata var/data/engines.EnginePolicy.json

# Start Supervisord (Celery workers)
echo "[+] Start Supervisord (Celery workers)"
supervisord -c var/etc/supervisord.conf

# Start server
echo "[+] Starting server"
gunicorn -b 0.0.0.0:8003 app.wsgi:application --timeout 120 --graceful-timeout 60
