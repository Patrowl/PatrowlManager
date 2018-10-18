from __future__ import absolute_import
import os
from celery import Celery
from django.conf import settings
from kombu import Exchange, Queue

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')

# set the default Django settings module for the 'celery' program.
app = Celery('app')
app.config_from_object('django.conf:settings')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

app.conf.task_queues = (
    # Default Queue / administrative purposes
    Queue('default', Exchange('default'), routing_key='default'),

    # Nmap
    Queue('scan-nmap', Exchange('scan'), routing_key='scan.nmap'),
    Queue('monitor-nmap', Exchange('monitor'), routing_key='monitor.nmap'),

    # Nessus
    Queue('scan-nessus', Exchange('scan'), routing_key='scan.nessus'),
    Queue('monitor-nessus', Exchange('monitor'), routing_key='monitor.nessus'),

    # Arachni
    Queue('scan-arachni', Exchange('scan'), routing_key='scan.arachni'),
    Queue('monitor-arachni', Exchange('monitor'), routing_key='monitor.arachni'),

    # SSLLabs
    Queue('scan-ssllabs', Exchange('scan'), routing_key='scan.ssllabs'),
    Queue('monitor-ssllabs', Exchange('monitor'), routing_key='monitor.ssllabs'),

    # SSLScan
    Queue('scan-sslscan', Exchange('scan'), routing_key='scan.sslscan'),
    Queue('monitor-sslscan', Exchange('monitor'), routing_key='monitor.sslscan'),

    # OWL_DNS
    Queue('scan-owl_dns', Exchange('scan'), routing_key='scan.owl_dns'),
    Queue('monitor-owl_dns', Exchange('monitor'), routing_key='monitor.owl_dns'),

    # OWL_LEAKS
    Queue('scan-owl_leaks', Exchange('scan'), routing_key='scan.owl_leaks'),
    Queue('monitor-owl_leaks', Exchange('monitor'), routing_key='monitor.owl_leaks'),

    # OWL_CODE
    Queue('scan-owl_code', Exchange('scan'), routing_key='scan.owl_code'),
    Queue('monitor-owl_code', Exchange('monitor'), routing_key='monitor.owl_code'),

    # VIRUSTOTAL
    Queue('scan-virustotal', Exchange('scan'), routing_key='scan.virustotal'),
    Queue('monitor-virustotal', Exchange('monitor'), routing_key='monitor.virustotal'),

    # URLVOID
    Queue('scan-urlvoid', Exchange('scan'), routing_key='scan.urlvoid'),
    Queue('monitor-urlvoid', Exchange('monitor'), routing_key='monitor.urlvoid'),

    # CENSYS
    Queue('scan-censys', Exchange('scan'), routing_key='scan.censys'),
    Queue('monitor-censys', Exchange('monitor'), routing_key='monitor.censys'),

    # CORTEX
    Queue('scan-cortex', Exchange('scan'), routing_key='scan.cortex'),
    Queue('monitor-cortex', Exchange('monitor'), routing_key='monitor.cortex'),

)
app.conf.task_default_queue = 'default'
app.conf.task_default_exchange = 'default'
app.conf.task_default_exchange_type = 'direct'
app.conf.task_default_routing_key = 'default'
