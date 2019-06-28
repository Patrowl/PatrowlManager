#!/bin/bash

## Starting Patrowl back-office server. MacOs compliant only.
source env3/bin/activate
if [ `ps waxu | grep -c postgres` -ne "1" ]; then
  echo "postgres db started. Nothing to do"
else
  echo -e "postgres db stopped. Start DB First !\nExiting."
  exit 1
fi

if [ `ps waxu | grep -c supervisord` -ne "1" ]; then
  echo "supervisord started. Nothing to do"
else
  echo -e "supervisord stopped. Starting supervisord."
  supervisord -c var/etc/supervisord.conf
fi
python manage.py makemigrations && \
python manage.py migrate && \
python manage.py collectstatic --noinput && \
gunicorn app.wsgi:application -b :8000 --timeout 300 --access-logfile -

deactivate
