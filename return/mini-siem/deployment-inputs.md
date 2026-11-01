# Deployment inputs

The fixture binding is not a production configuration. The deployment owner
must supply the following without committing credentials:

| Input | Owner | Required before enablement |
|---|---|---|
| HTTPS origin and resolved-address allowlist | Network/deployment owner | Yes |
| Server certificate chain, hostname and trust bundle reference | PKI owner | Yes |
| Tenant ID and integration instance ID | Dashboard owner | Yes |
| Source instance ID | mini-SIEM owner | Yes |
| Dedicated reader principal and secret-manager reference | Security owner | Yes |
| Database owner credential for one-time schema initialization | DB owner | Yes |
| PostgreSQL split-role grants refresh | DB owner | PostgreSQL only |
| G3 worker-origin reachability/TLS evidence | Dashboard/deployment owner | Yes |

Unknown deployment values remain `null` in
`binding.deployment.template.json`. The template is deliberately disabled and
is not deployable as returned.
