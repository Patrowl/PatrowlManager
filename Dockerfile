FROM python:3.7
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Patrowl Manager" Version="1.1.2"

ENV PYTHONUNBUFFERED 1
RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/

RUN apt-get update -yq
# RUN apt-get install -yq --no-install-recommends apt-utils python3 python3-pip python3-virtualenv libmagic-dev
RUN apt-get install -yq --no-install-recommends apt-utils python3 python3-pip libmagic-dev
RUN apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD ./requirements.txt /root/

RUN python --version
RUN pip3 install virtualenv
RUN virtualenv env3
RUN /opt/patrowl-manager/env3/bin/pip3 install -r /root/requirements.txt

COPY . /opt/patrowl-manager/
COPY app/settings.py.sample /opt/patrowl-manager/app/settings.py

EXPOSE 8003
ENTRYPOINT ["/opt/patrowl-manager/docker-entrypoint.sh"]
CMD ["run"]
