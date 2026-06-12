import os, sys
sys.path.insert(0, '/authentik')
sys.path.insert(0, '/ak-root/venv/lib/python3.12/site-packages')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()
from django.contrib.auth import get_user_model
from authentik.core.models import Group, Token
from authentik.providers.oauth2.models import OAuth2Provider, RedirectURI, RedirectURIMatchingMode
from authentik.core.models import Application
from authentik.flows.models import Flow
from authentik.crypto.models import CertificateKeyPair

User = get_user_model()

# Create groups
for name in ['admin-group', 'ops-group', 'dev-group']:
    Group.objects.get_or_create(name=name)
    print(f"Group: {name}")

# Create users
for username, group_name, password in [('admin','admin-group','123123'),('ops','ops-group','123123'),('dev','dev-group','123123')]:
    user, _ = User.objects.get_or_create(username=username)
    user.set_password(password)
    user.ak_groups.add(Group.objects.get(name=group_name))
    user.save()
    print(f"User: {username}")

# Find or create authorization flow
auth_flow = Flow.objects.filter(designation='authorization').first()
if not auth_flow:
    # Create one from the default blueprint
    print("No authorization flow found, waiting 5s and retrying...")
    import time
    time.sleep(5)
    auth_flow = Flow.objects.filter(designation='authorization').first()

inval_flow = Flow.objects.filter(slug='default-invalidation-flow').first()

if auth_flow:
    redirect_uris_list = [
        "http://localhost:8200/oidc/callback",
        "https://localhost:8200/oidc/callback",
        "http://localhost:8200/ui/vault/auth/oidc/oidc/callback",
        "https://localhost:8200/ui/vault/auth/oidc/oidc/callback",
        "http://localhost:8200/v1/auth/oidc/oidc/callback",
        "https://localhost:8200/v1/auth/oidc/oidc/callback",
    ]
    prov, _ = OAuth2Provider.objects.get_or_create(
        name='Vault OIDC',
        defaults={
            'authorization_flow': auth_flow,
            'invalidation_flow': inval_flow,
            'client_id': 'vault-client-id',
            'client_secret': 'vault-client-secret',
            'redirect_uris': [
                RedirectURI(matching_mode=RedirectURIMatchingMode.STRICT, url=u)
                for u in redirect_uris_list
            ],
        }
    )
    print(f"OIDC Provider: {prov.name}")

    key = CertificateKeyPair.objects.first()
    if key and not prov.signing_key:
        prov.signing_key = key
        prov.save()
        print(f"Signing key: {key.name}")

    app, _ = Application.objects.get_or_create(
        slug='vault',
        defaults={'name': 'Vault', 'provider': prov},
    )
    print(f"Application: {app.name}")
else:
    print(f"ERROR: No authorization flow available! Cannot create OIDC provider.")
    print(f"Flows in DB: {[f.slug for f in Flow.objects.all()]}")

print("\n=== Done ===")
