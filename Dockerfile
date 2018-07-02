FROM python:2
#ENV PYTHONUNBUFFERED 1
RUN mkdir -p /opt/patrowl-manager/
WORKDIR /opt/patrowl-manager/
ADD . /opt/patrowl-manager/
RUN pip install -r requirements.txt
#ADD . /opt/patrowl-manager/

#COPY docker-entrypoint.sh /opt/patrowl-manager/docker-entrypoint.sh
# ENTRYPOINT ["/patrowl-app/docker-entrypoint.sh"]
# RUN ls -al
# RUN pwd
ENTRYPOINT ["./docker-entrypoint.sh"]
