# Generated by Django 2.1.5 on 2019-01-14 08:57

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0021_auto_20190112_2005'),
    ]

    operations = [
        migrations.AlterField(
            model_name='member',
            name='project',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.Project'),
        ),
    ]
