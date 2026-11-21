# Certificates

A small PKI playground: build a self-signed root CA, an intermediate CA signed
by the root, and a leaf (server) certificate signed by the intermediate, then
serve it over TLS with nginx via Docker Compose.

## Layout

- `simple-operator.sh` — builds the full chain: root CA → intermediate CA →
  leaf cert (`nature-life.com`), then verifies and inspects each cert. The
  root and intermediate keys are AES-256 encrypted, so `openssl genrsa` will
  prompt for a passphrase the first time each is created — see
  `passwords.txt` for the demo values. Generated material is written to
  `root/` (gitignored).
- `openssl.cnf` — shared CA config used by both root and intermediate
  (`CA_DIR` env var selects which directory each `openssl` invocation acts
  on). Defines `policy_strict` (root → intermediate) and `policy_loose`
  (intermediate → leaf), plus the `v3_ca` / `v3_intermediate_ca` /
  `server_cert` extension blocks.
- `compose.yaml` + `nginx/nginx.conf` — nginx container that terminates TLS
  using the generated leaf fullchain/key, for a quick "does the chain
  actually work in a browser/curl" check.
- `passwords.txt` — demo-only passwords for the root/intermediate private
  keys. Not meant for anything beyond local experimentation.

## Build the chain

```bash
./simple-operator.sh
```

This creates `root/ca` (root CA) and `root/ca/intermediate` (intermediate CA
+ leaf cert for `nature-life.com`), verifying each link and printing
issuer/subject/dates for the root and intermediate certs.

## Serve it over TLS

```bash
docker compose up
```

nginx listens on `localhost:8002` (HTTPS) using
`root/ca/intermediate/certs/nature-life.com.fullchain.pem` and the matching
private key. Since the root CA isn't trusted by your system, verify with:

```bash
curl --cacert root/ca/certs/ca.cert.pem https://staging.nature-life.com:8002/ \
  --resolve staging.nature-life.com:8002:127.0.0.1
```

## Inspecting certs

### Get a cert's subject and issuer
```bash
openssl crl2pkcs7 -nocrl -certfile <file.pem> \
  | openssl pkcs7 -print_certs -noout | grep -E 'subject|issuer'
```

### Inspect essential information
```bash
openssl x509 -in <file.pem> -noout -issuer -subject -dates -ext subjectAltName
```
