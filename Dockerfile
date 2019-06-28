FROM python:3
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Patrowl Manager" Version="1.1.0"

ENV PYTHONUNBUFFERED 1
RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/
COPY . /opt/patrowl-manager/
COPY app/settings.py.sample /opt/patrowl-manager/app/settings.py

RUN apt-get update -yq
RUN apt-get install -yq --no-install-recommends apt-utils python3 python3-pip python3-virtualenv libmagic-dev
# RUN apt-get install -yq --no-install-recommends python3 python3-pip python3-venv libmagic-dev
#RUN apt-get install -yq --no-install-recommends virtualenv python3-pip libmagic-dev
RUN apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

#RUN pip3 install --user virtualenv
RUN python --version
RUN pip install --user virtualenv
#RUN virtualenv env3
# RUN python3 -m venv env3
# RUN python3 -m virtualenv env3
# RUN python3 -m virtualenv --python=/usr/bin/python3 env3
# RUN python3 -m virtualenv env3

# RUN /bin/bash -c "source env3/bin/activate && pip3 install -r requirements.txt && deactivate"
RUN /bin/bash -c "source env3/bin/activate && pip3 install -r requirements.txt && deactivate"
# RUN ls -al env3/bin/
# RUN env3/bin/python --version
# RUN env3/bin/pip install -r requirements.txt

EXPOSE 8003
ENTRYPOINT ["/opt/patrowl-manager/docker-entrypoint.sh"]
CMD ["run"]
