# Generated by Django 5.0.2 on 2024-03-15 18:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Backend', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='cargos',
            old_name='nombre',
            new_name='nombre_cargo',
        ),
        migrations.RenameField(
            model_name='roles',
            old_name='nombre',
            new_name='nombre_rol',
        ),
        migrations.RenameField(
            model_name='unidades',
            old_name='nombre',
            new_name='nombre_unidad',
        ),
    ]
