# Generated manually

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ecomm_tenant_admins', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='tenantcrmclient',
            old_name='contactperson_email',
            new_name='contact_person_email',
        ),
        migrations.AlterModelTable(
            name='tenantcrmclient',
            table='ecomm_tenant_admins_crmclients',
        ),
    ]
