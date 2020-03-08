#!/bin/bash
export DB_HOST=${DB_HOST:-db}
export RABBITMQ_HOST=${RABBITMQ_HOST:-rabbitmq}

echo "[+] Wait for DB availability"
while !</dev/tcp/$DB_HOST/5432; do sleep 1; done

echo "[+] Wait for RabbitMQ availability"
while !</dev/tcp/$RABBITMQ_HOST/5672; do sleep 1; done

source env3/bin/activate

# Collect static files
echo "[+] Collect static files"
python manage.py collectstatic --noinput

# Apply database migrations
echo "[+] Make database migrations"
python manage.py makemigrations

# Apply database migrations
echo "[+] Apply database migrations"
python manage.py migrate

# Check for first install
if [ ! -f status.created ]; then
  # Create the default admin user
  echo "[+] Create the default admin user"
  echo "\
from django.contrib.auth import get_user_model; \
User = get_user_model(); \
User.objects.create_superuser('admin', 'admin@dev.patrowl.io', 'Bonjour1!') if User.objects.count() == 0 else pass" | python manage.py shell
  # Populate the db with default data
  echo "[+] Populate the db with default data"
  python manage.py loaddata var/data/assets.AssetCategory.json
  python manage.py loaddata var/data/engines.Engine.json
  python manage.py loaddata var/data/engines.EnginePolicyScope.json
  python manage.py loaddata var/data/engines.EnginePolicy.json

  touch status.created
fi

# Start Supervisord (Celery workers)
echo "[+] Start Supervisord (Celery workers)"
supervisord -c var/etc/supervisord.conf

# Configure engines and turn-on auto-refresh engine status
if [ -f set_engines.py ]; then
  python manage.py shell < set_engines.py
fi

# Start server
echo "[+] Starting server"
gunicorn -b 0.0.0.0:8003 app.wsgi:application --timeout 300
