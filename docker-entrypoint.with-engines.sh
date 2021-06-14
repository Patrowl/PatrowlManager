#!/bin/bash
export POSTGRES_HOST=${POSTGRES_HOST:-db}
export POSTGRES_PORT=${POSTGRES_PORT:-5432}
export RABBITMQ_HOST=${RABBITMQ_HOST:-rabbitmq}
export RABBITMQ_PORT=${RABBITMQ_PORT:-5672}
# export UPDATE_DB_SCHEMA=${UPDATE_DB_SCHEMA:-0}

echo "[+] Wait for DB availability"
while !</dev/tcp/$POSTGRES_HOST/$POSTGRES_PORT; do sleep 1; done

echo "[+] Wait for RabbitMQ availability"
while !</dev/tcp/$RABBITMQ_HOST/$RABBITMQ_PORT; do sleep 1; done

source env3/bin/activate

echo "[+] PatrowlManager version"
cat VERSION

# Collect static files
echo "[+] Collect static files"
python manage.py collectstatic --noinput

echo "[+] Update DB schema (if already created)"
var/bin/update_db_migrations.sh

# Apply database migrations
echo "[+] Make database migrations"
echo " - scans"
python manage.py makemigrations scans
echo " - findings"
python manage.py makemigrations findings
echo " - events"
python manage.py makemigrations events
echo " - ... and all the rest"
python manage.py makemigrations

# Apply database migrations
echo "[+] Apply database migrations"
python manage.py migrate

# Check for first install
if [ ! -f status.created ]; then
  # Create the default admin user
  echo "[+] Create the default admin user (if needeed)"
  python manage.py shell < var/bin/create_default_admin.py

  echo "[+] Create default team if needed"
  python manage.py shell < var/bin/create_default_team.py

  # Populate the db with default data
  echo "[+] Populate the db with default data"
  python manage.py loaddata var/data/assets.AssetCategory.json
  python manage.py loaddata var/data/engines.Engine.json
  python manage.py loaddata var/data/engines.EnginePolicyScope.json
  python manage.py loaddata var/data/engines.EnginePolicy.json

  echo "[+] Configure the engines nmap, sslscan and owl_dns"
  echo -e "\r\
from engines.models import Engine, EngineInstance\r\
try:\r\
    EngineInstance(engine=Engine.objects.filter(name=\"NMAP\").first(), name=\"nmap-local-001\", api_url=\"http://engine-nmap:5001/engines/nmap/\").save()\r\
    EngineInstance(engine=Engine.objects.filter(name=\"SSLSCAN\").first(), name=\"sslscan-local-001\", api_url=\"http://engine-sslscan:5014/engines/sslscan/\").save()\r\
    EngineInstance(engine=Engine.objects.filter(name=\"OWL_DNS\").first(), name=\"owl_dns-local-001\", api_url=\"http://engine-owl_dns:5006/engines/owl_dns/\").save()\r\
except Exception:\r\
    pass" | python manage.py shell

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
