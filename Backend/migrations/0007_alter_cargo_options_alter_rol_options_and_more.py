# Generated by Django 5.0.2 on 2024-04-05 20:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Backend', '0006_alter_cargo_options_alter_rol_options_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='cargo',
            options={'managed': False},
        ),
        migrations.AlterModelOptions(
            name='rol',
            options={'managed': False},
        ),
        migrations.AlterModelOptions(
            name='unidad',
            options={'managed': False},
        ),
        migrations.AlterModelOptions(
            name='usuario',
            options={'managed': False},
        ),
    ]
