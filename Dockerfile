FROM python:3.7-slim
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="PatrowlManager" Version="1.6.26"

ENV PYTHONUNBUFFERED 1
ARG arg_http_proxy
ENV http_proxy $arg_http_proxy
ENV https_proxy $arg_http_proxy

RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/

RUN apt-get update -yq  \
	&& apt-get install -yq --no-install-recommends apt-utils python3 python3-pip libmagic-dev python3-dev gcc wget \
	&& apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD ./requirements.txt /root/

#RUN python --version \
#	&& pip3 install virtualenv \
#	&& virtualenv env3 \
#	&& /opt/patrowl-manager/env3/bin/pip3 install --no-cache-dir -r /root/requirements.txt

RUN python --version \
	&& pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org --default-timeout=100 virtualenv \
	&& virtualenv env3 \
	&& /opt/patrowl-manager/env3/bin/pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org --trusted-host pypi.python.org --default-timeout=100 --no-cache-dir -r /root/requirements.txt

COPY . /opt/patrowl-manager/
COPY app/settings.py.sample /opt/patrowl-manager/app/settings.py

EXPOSE 8003
ENTRYPOINT ["/opt/patrowl-manager/docker-entrypoint.sh"]
CMD ["run"]
