# Generated by Django 2.2.16 on 2020-09-21 09:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assets', '0007_auto_20200709_0007'),
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='exposure',
            field=models.CharField(choices=[('external', 'External'), ('internal', 'Internal'), ('restricted', 'Restricted')], default='external', max_length=16),
        ),
    ]
