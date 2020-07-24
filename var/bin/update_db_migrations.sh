if echo "from django.db import connection ; print('assets' in connection.introspection.table_names()) " | python manage.py shell | grep -q 'True'; then

    echo "-- Clean the django_migrations table"
    echo "from django.db import connection; cursor = connection.cursor(); cursor.execute('delete from django_migrations')" | python manage.py shell

    echo "-- Remove 'migrations' folders"
    rm -rf events/migrations
    rm -rf users/migrations
    rm -rf scans/migrations
    rm -rf assets/migrations
    rm -rf findings/migrations
    rm -rf rules/migrations
    rm -rf settings/migrations

    echo "-- Apply fake migrations for built-in apps"
    python manage.py migrate --fake

    echo "-- Run syncdb on every apps"
    python manage.py migrate events --run-syncdb
    python manage.py migrate users --run-syncdb
    python manage.py migrate scans --run-syncdb
    python manage.py migrate assets --run-syncdb
    python manage.py migrate findings --run-syncdb
    python manage.py migrate rules --run-syncdb
    python manage.py migrate settings --run-syncdb

    echo "-- Make migrations on every apps"
    python manage.py makemigrations events
    python manage.py makemigrations users
    python manage.py makemigrations scans
    python manage.py makemigrations assets
    python manage.py makemigrations findings
    python manage.py makemigrations rules
    python manage.py makemigrations settings

    echo "-- Apply migration (fake initial)"
    python manage.py migrate --fake-initial
fi
