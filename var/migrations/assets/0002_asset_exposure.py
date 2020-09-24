from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('assets', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='asset',
            name='exposure',
            field=models.CharField(choices=[('external', 'External'), ('internal', 'Internal'), ('restricted', 'Restricted')], default='external', max_length=16),
        ),
        migrations.AlterField(
            model_name='asset',
            name='exposure',
            field=models.CharField(choices=[('unknown', 'Unknown'), ('external', 'External'), ('internal', 'Internal'), ('restricted', 'Restricted')], default='unknown', max_length=16),
        ),
    ]
