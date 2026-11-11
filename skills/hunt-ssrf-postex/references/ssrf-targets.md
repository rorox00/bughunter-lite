# SSRF post-ex target map

Where to point a confirmed SSRF. Priority is localhost → link-local/metadata →
internal ranges. Everything is reached BY THE SERVER; you observe via full-read,
`diffr.diff` (status/length/timing), or `oast` for blind. Read-only: show the
response, never replay returned credentials.

## Priority order
1. `127.0.0.1` / `::1` / `localhost` — services bound loopback-only that trust
   any local caller (the richest target).
2. Link-local / cloud metadata: `169.254.169.254` (and `fd00:ec2::254`).
3. Internal DNS names and private ranges: `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, container/service names, `*.internal`/`*.svc.cluster.local`.

## Common internal ports / services to probe
- Web/admin: `80`, `443`, `8080`, `8443`, `8000`, `3000`, `9000`.
- Service-mesh / proxy admin: Envoy admin `9901`, HAProxy/Traefik dashboards.
- App mgmt: Spring Boot actuator (`/actuator`, `/actuator/env`,
  `/actuator/heapdump`), `/metrics`, `/debug`, `/health`, `/status`.
- Datastores (often unauth internally): Redis `6379`, Memcached `11211`,
  Elasticsearch `9200`, Mongo `27017`, Postgres `5432`, MySQL `3306`,
  RabbitMQ mgmt `15672`, Kafka `9092`.
- Orchestration: Kubernetes API `6443`/kubelet `10250`, Docker API `2375`,
  Consul `8500`, etcd `2379`, Nomad `4646`.
- CI/CD & tooling consoles bound internally.

## Cloud metadata (confirm reachability + header-settability first)
- **AWS IMDS**: `http://169.254.169.254/latest/meta-data/`; IMDSv2 requires a
  PUT-issued token header — only pursue if the SSRF can set that header.
- **GCP**: `http://metadata.google.internal/computeMetadata/v1/` with header
  `Metadata-Flavor: Google`.
- **Azure**: `http://169.254.169.254/metadata/instance?api-version=...` with
  header `Metadata: true`.
- Show the metadata document as proof; STOP there — do not use any IAM/role
  credentials it exposes (`proof_note:"creds reachable, NOT used"`).

## Confirmation notes
- No body reflected → infer open/closed from `diffr.diff` on status/length and
  connect-vs-refuse timing; confirm blind reach with an `oast` callback.
- Capture the exact pivot request + the internal response; the internal/admin/
  metadata access IS the finding.
