"""Authentik initialization: creates groups, users, OIDC provider, signing key."""
import os, sys
sys.path.insert(0, '/authentik')
sys.path.insert(0, '/ak-root/venv/lib/python3.12/site-packages')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
import django
django.setup()

from django.contrib.auth import get_user_model
from authentik.core.models import Group
from authentik.providers.oauth2.models import OAuth2Provider, RedirectURI, RedirectURIMatchingMode
from authentik.core.models import Application
from authentik.flows.models import Flow
from authentik.crypto.models import CertificateKeyPair

User = get_user_model()

# Create groups
for name in ['admin-group', 'ops-group', 'dev-group']:
    Group.objects.get_or_create(name=name)
    print(f"Group: {name}")

# Create users with passwords
for username, group_name, password in [
    ('admin', 'admin-group', '123123'),
    ('ops', 'ops-group', '123123'),
    ('dev', 'dev-group', '123123'),
]:
    user, created = User.objects.get_or_create(username=username)
    if created:
        user.set_password(password)
    user.ak_groups.add(Group.objects.get(name=group_name))
    user.save()
    print(f"User: {username}")

# Get authorization flow
auth_flow = Flow.objects.filter(
    slug='default-provider-authorization-implicit-consent'
).first()
if not auth_flow:
    auth_flow = Flow.objects.filter(designation='authorization').order_by('pk').first()

inval_flow = Flow.objects.filter(slug='default-invalidation-flow').first()

if auth_flow:
    redirect_uris = [
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
                for u in redirect_uris
            ],
        }
    )
    print(f"OIDC Provider: {prov.name}")

    # Assign signing key for RS256 (required by Vault)
    key = CertificateKeyPair.objects.first()
    if key and not prov.signing_key:
        prov.signing_key = key
        prov.save()
        print(f"Signing key: {key.name}")

    # Create application
    app, _ = Application.objects.get_or_create(
        slug='vault',
        defaults={'name': 'Vault', 'provider': prov},
    )
    print(f"Application: {app.name}")

print("\n=== Done ===")
