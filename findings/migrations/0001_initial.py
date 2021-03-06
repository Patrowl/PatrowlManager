# Generated by Django 2.2.5 on 2019-09-17 23:07

from django.conf import settings
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('scans', '0001_initial'),
        ('engines', '0001_initial'),
        ('assets', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='RawFinding',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('asset_name', models.CharField(max_length=256)),
                ('task_id', models.UUIDField(default=uuid.uuid4)),
                ('title', models.CharField(max_length=256)),
                ('type', models.CharField(max_length=50)),
                ('hash', models.CharField(max_length=256)),
                ('confidence', models.CharField(max_length=10)),
                ('severity', models.CharField(choices=[('info', 'info'), ('low', 'low'), ('medium', 'medium'), ('high', 'high'), ('critical', 'critical')], default='info', max_length=10)),
                ('severity_num', models.IntegerField(blank=True, default=1, null=True)),
                ('description', models.TextField()),
                ('solution', models.TextField(blank=True, null=True)),
                ('raw_data', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('risk_info', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('vuln_refs', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('links', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('tags', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('status', models.CharField(choices=[('new', 'New'), ('ack', 'Acknowledged'), ('mitigated', 'Mitigated'), ('confirmed', 'Confirmed'), ('patched', 'Patched'), ('closed', 'Closed'), ('false-positive', 'False-Positive')], max_length=16)),
                ('engine_type', models.CharField(max_length=20)),
                ('found_at', models.DateTimeField(blank=True, null=True)),
                ('checked_at', models.DateTimeField(blank=True, null=True)),
                ('comments', models.TextField(blank=True, default='n/a', null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='assets.Asset')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='scans.Scan')),
                ('scopes', models.ManyToManyField(blank=True, to='engines.EnginePolicyScope')),
            ],
            options={
                'db_table': 'raw_findings',
            },
        ),
        migrations.CreateModel(
            name='Finding',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('asset_name', models.CharField(max_length=256)),
                ('task_id', models.UUIDField(default=uuid.uuid4)),
                ('title', models.CharField(default='title', max_length=256)),
                ('type', models.CharField(max_length=50)),
                ('hash', models.CharField(max_length=256)),
                ('confidence', models.CharField(max_length=10)),
                ('severity', models.CharField(choices=[('info', 'info'), ('low', 'low'), ('medium', 'medium'), ('high', 'high'), ('critical', 'critical')], default='info', max_length=10)),
                ('severity_num', models.IntegerField(blank=True, default=1, null=True)),
                ('description', models.TextField()),
                ('solution', models.TextField(blank=True, null=True)),
                ('raw_data', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('risk_info', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('vuln_refs', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('links', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('tags', django.contrib.postgres.fields.jsonb.JSONField(blank=True, null=True)),
                ('status', models.CharField(choices=[('new', 'New'), ('ack', 'Acknowledged'), ('mitigated', 'Mitigated'), ('confirmed', 'Confirmed'), ('patched', 'Patched'), ('closed', 'Closed'), ('false-positive', 'False-Positive')], default='new', max_length=16)),
                ('engine_type', models.CharField(max_length=20)),
                ('found_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('comments', models.TextField(blank=True, default='n/a', null=True)),
                ('checked_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='assets.Asset')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
                ('raw_finding', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='findings.RawFinding')),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='scans.Scan')),
                ('scopes', models.ManyToManyField(blank=True, to='engines.EnginePolicyScope')),
            ],
            options={
                'db_table': 'findings',
            },
        ),
    ]
