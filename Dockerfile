FROM python:2.7
#FROM python:2.7-slim
ENV PYTHONUNBUFFERED 1
RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/
COPY . /opt/patrowl-manager/
COPY app/settings.py.sample /opt/patrowl-manager/app/settings.py

RUN apt-get update -yq
RUN apt-get install -yq --no-install-recommends virtualenv python-pip libmagic-dev
RUN apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN virtualenv env
RUN /bin/bash -c "source env/bin/activate && pip install -r requirements.txt && deactivate"

EXPOSE 8001
ENTRYPOINT ["/opt/patrowl-manager/docker-entrypoint.sh"]
CMD ["run"]
