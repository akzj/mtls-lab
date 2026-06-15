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
    user.name = username
    user.email = f'{username}@lab.local'
    user.ak_groups.add(Group.objects.get(name=group_name))
    user.save()
    print(f"User: {username}")

# Find or create authorization flow
auth_flow = Flow.objects.filter(designation='authorization').first()
if not auth_flow:
    print("No authorization flow found, waiting for it (up to 30s)...")
    import time
    for i in range(15):
        time.sleep(2)
        auth_flow = Flow.objects.filter(designation='authorization').first()
        if auth_flow:
            print("  Authorization flow ready after ~{}s".format((i+1)*2))
            break
    else:
        print("  Authorization flow still not available after 30s, continuing anyway")

inval_flow = Flow.objects.filter(slug='default-invalidation-flow').first()

if auth_flow:
    redirect_uris_list = [
        "http://vault.lab.local:8200/oidc/callback",
        "https://vault.lab.local:8200/oidc/callback",
        "http://vault.lab.local:8200/ui/vault/auth/oidc/oidc/callback",
        "https://vault.lab.local:8200/ui/vault/auth/oidc/oidc/callback",
        "http://vault.lab.local:8200/v1/auth/oidc/oidc/callback",
        "https://vault.lab.local:8200/v1/auth/oidc/oidc/callback",
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

# Create Go Server OIDC application
print("")
if auth_flow:
    go_server_redirect_uris = [
        "http://web.lab.local:9091/auth/callback",
        "https://web.lab.local:9091/auth/callback",
    ]
    go_prov, _ = OAuth2Provider.objects.get_or_create(
        name='Go Server',
        defaults={
            'authorization_flow': auth_flow,
            'invalidation_flow': inval_flow,
            'client_id': 'go-server-client-id',
            'client_secret': 'go-server-client-secret',
            'redirect_uris': [
                RedirectURI(matching_mode=RedirectURIMatchingMode.STRICT, url=u)
                for u in go_server_redirect_uris
            ],
        }
    )
    print(f"OIDC Provider: {go_prov.name}")

    if key and not go_prov.signing_key:
        go_prov.signing_key = key
        go_prov.save()
        print(f"Signing key: {key.name}")

    go_app, _ = Application.objects.get_or_create(
        slug='go-server',
        defaults={'name': 'Go Server', 'provider': go_prov, 'meta_launch_url': 'http://web.lab.local:9091/'},
    )
    print(f"Application: {go_app.name}")

    # Create scope mappings for name and email claims
    from authentik.providers.oauth2.models import ScopeMapping
    sm_name, _ = ScopeMapping.objects.get_or_create(
        name='Profile - Name',
        defaults={'scope_name': 'profile', 'expression': 'return {"name": user.name}'},
    )
    sm_email, _ = ScopeMapping.objects.get_or_create(
        name='Email - Email',
        defaults={'scope_name': 'email', 'expression': 'return {"email": user.email}'},
    )
    sm_groups, _ = ScopeMapping.objects.get_or_create(
        name='Profile - Groups',
        defaults={'scope_name': 'profile', 'expression': 'return {"groups": [g.name for g in user.ak_groups.all()]}'},
    )
    for p in [prov, go_prov]:
        if sm_name not in p.property_mappings.all():
            p.property_mappings.add(sm_name)
        if sm_email not in p.property_mappings.all():
            p.property_mappings.add(sm_email)
        if sm_groups not in p.property_mappings.all():
            p.property_mappings.add(sm_groups)
    print("Scope mappings added ✅")
else:
    print("ERROR: No authorization flow available! Cannot create Go Server OIDC provider.")

print("\n=== Done ===\n")
