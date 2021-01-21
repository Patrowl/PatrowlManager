FROM python:3.7-slim
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="PatrowlManager" Version="1.6.11"

ENV PYTHONUNBUFFERED 1
RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/

RUN apt-get update -yq  \
	&& apt-get install -yq --no-install-recommends apt-utils python3 python3-pip libmagic-dev python3-dev gcc \
	&& apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD ./requirements.txt /root/

RUN python --version \
	&& pip3 install virtualenv \
	&& virtualenv env3 \
	&& /opt/patrowl-manager/env3/bin/pip3 install --no-cache-dir -r /root/requirements.txt

COPY . /opt/patrowl-manager/
COPY app/settings.py.sample /opt/patrowl-manager/app/settings.py

EXPOSE 8003
ENTRYPOINT ["/opt/patrowl-manager/docker-entrypoint.sh"]
CMD ["run"]
