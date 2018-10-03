FROM python:2.7
ENV PYTHONUNBUFFERED 1
RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/
COPY . /opt/patrowl-manager/
RUN pip install -r requirements.txt
RUN python manage.py collectstatic --no-input

EXPOSE 8001
CMD ["gunicorn", "--bind", ":8000", "app.wsgi:application"]
