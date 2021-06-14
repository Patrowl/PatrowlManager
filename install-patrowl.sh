#!/bin/bash
# Installation script for PatrowlManager and few engines
# Copyright (C) 2020 Nicolas Mattiocco - @MaKyOtOx
# Licensed under the AGPLv3 License

echo "[+] Setting variables if not set in env"
# PG Database
DB_HOST = ${POSTGRES_HOST:-localhost}
DB_PORT = ${POSTGRES_PORT:-5432}
# RabbitMQ
RABBITMQ_HOST = ${RABBITMQ_HOST:-rabbitmq}
RABBITMQ_PORT = ${RABBITMQ_PORT:-5672}
# PatrowlEngines
PE_INSTALL_PATH = ${PE_INSTALL_PATH:-"$PWD/../"}
# PatrowlManager
SU_USERNAME = ${PATROWL_SU_USERNAME:-"admin"}
SU_EMAIL = ${PATROWL_SU_EMAIL:-"admin@dev.patrowl.io"}
SU_PASSWORD = ${PATROWL_SU_PASSWORD:-"Bonjour1!"}

echo "[+] Install OS dependencies"
sudo apt install build-essential python3 python3-dev git curl rabbitmq-server postgresql postgresql-client nginx
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo python3 get-pip.py
rm get-pip.py
sudo pip3 install virtualenv

echo "[+] Install PatrowlEngines"
git clone https://github.com/Patrowl/PatrowlEngines $PE_INSTALL_PATH


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

echo "[+] Checking status of Celery workers"
sleep 2
supervisorctl status all

# Configure engines and turn-on auto-refresh engine status
# if [ -f set_engines.py ]; then
#   python manage.py shell < set_engines.py
# fi

# Start Gunicorn WSGI server
echo "[+] Starting server"
gunicorn -b 0.0.0.0:8003 app.wsgi:application --timeout 300
