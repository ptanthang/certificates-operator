#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------------------
# PKI cheat sheet
# ----------------------------------------------------------------------------
# Private key: one per identity (root CA, intermediate CA, each leaf).
#   - never shared, never reused across entities.
#
# CSR: generate only when someone ELSE will sign the cert.
#   - root CA     -> key, NO csr (self-signs via `req -x509`)
#   - intermediate-> key + csr (root signs it)
#   - leaf        -> key + csr (intermediate signs it)
#
# Policy:
#   - root signs intermediate -> policy_strict (C/ST/O must match root)
#   - intermediate signs leaf -> policy_loose  (leaves vary)
# ----------------------------------------------------------------------------

CONF="./openssl.cnf"
ROOT_DIR="./root/ca"
INTERMEDIATE_DIR="$ROOT_DIR/intermediate"
LEAF_NAME="nature-life.com"

ROOT_SUBJ="/C=VN/ST=Vietname/O=Nature Life Ltd/CN=Nature Life Ltd Root CA"
INT_SUBJ="/C=VN/ST=Vietname/O=Nature Life Ltd/CN=Nature Life Ltd Intermediate CA"
LEAF_SUBJ="/C=VN/ST=Vietname/O=Nature Life Ltd/CN=$LEAF_NAME"

declare -rA COLOR_PALETTE=(
  [BOLD]=$'\033[1m' [RED]=$'\033[31m' [GREEN]=$'\033[32m'
  [YELLOW]=$'\033[33m' [BLUE]=$'\033[34m' [RESET]=$'\033[0m'
)

log() {
  local level="$1"; shift
  local color
  case "$level" in
    INFO)    color="${COLOR_PALETTE[BOLD]}${COLOR_PALETTE[BLUE]}" ;;
    SUCCESS) color="${COLOR_PALETTE[BOLD]}${COLOR_PALETTE[GREEN]}" ;;
    WARN)    color="${COLOR_PALETTE[BOLD]}${COLOR_PALETTE[YELLOW]}" ;;
    ERROR)   color="${COLOR_PALETTE[BOLD]}${COLOR_PALETTE[RED]}" ;;
    *) printf 'log: unknown level %q\n' "$level" >&2; return 2 ;;
  esac
  printf '%s[%s]%s %s\n' "$color" "$level" "${COLOR_PALETTE[RESET]}" "$*"
}

sign_cert() {
  local label="$1" cfg="$2"; shift 2
  if [[ "${DEBUG:-0}" == "1" ]] && command -v strace >/dev/null; then
    local out="openssl.${label}.trace"
    log WARN "strace enabled -> $out"
    strace -f -e trace=openat,openat2,access -o "$out" \
      openssl ca -config "$cfg" "$@"
  else
    openssl ca -config "$cfg" "$@"
  fi
}

inspect_cert() {
  local crt=$1
  log INFO "Inspecting $crt"
  openssl x509 -in "$crt" -noout -issuer -subject -dates -ext subjectAltName
}

# openssl 3.x eagerly resolves $ENV::SAN at config load time; give it a
# harmless default so root/intermediate signing (which never reads
# [ server_cert ]) doesn't trip on an unset variable.
export SAN="${SAN:-DNS:unused}"

init_ca_directories() {
  local dir=$1
  mkdir -p "$dir"/{certs,crl,csr,newcerts,private}
  chmod 700 "$dir/private"
  [[ -f $dir/index.txt ]] || : > "$dir/index.txt"
  [[ -f $dir/serial    ]] || echo 1000 > "$dir/serial"
}

gen_private_key() {
  local path=$1 bits=$2 enc=${3:-}
  if [[ -f $path ]]; then
    log WARN "key exists, skipping: $path"
    return
  fi
  openssl genrsa ${enc:+$enc} -out "$path" "$bits"
  chmod 400 "$path"
}

create_root() {
  log INFO "Creating root CA"
  init_ca_directories "$ROOT_DIR"

  gen_private_key "$ROOT_DIR/private/ca.key.pem" 4096 -aes256

  if [[ -f $ROOT_DIR/certs/ca.cert.pem ]]; then
    log WARN "root cert exists, skipping"
  else
    CA_DIR="$ROOT_DIR" openssl req -config "$CONF" -x509 -new -sha256 \
      -key "$ROOT_DIR/private/ca.key.pem" -days 7300 \
      -extensions v3_ca -subj "$ROOT_SUBJ" \
      -out "$ROOT_DIR/certs/ca.cert.pem"
    chmod 444 "$ROOT_DIR/certs/ca.cert.pem"
  fi
  log SUCCESS "Root CA ready"
}

create_intermediate() {
  log INFO "Creating intermediate CA"
  init_ca_directories "$INTERMEDIATE_DIR"

  gen_private_key "$INTERMEDIATE_DIR/private/ca.key.pem" 4096 -aes256

  if [[ -f $INTERMEDIATE_DIR/csr/intermediate.csr.pem ]]; then
    log WARN "intermediate CSR exists, skipping"
  else
    log INFO "Generating intermediate CSR"
    CA_DIR="$INTERMEDIATE_DIR" openssl req -config "$CONF" -new -sha256 \
      -key "$INTERMEDIATE_DIR/private/ca.key.pem" -subj "$INT_SUBJ" \
      -out "$INTERMEDIATE_DIR/csr/intermediate.csr.pem"
  fi

  if [[ -f $INTERMEDIATE_DIR/certs/ca.cert.pem ]]; then
    log WARN "intermediate cert exists, skipping"
  else
    log INFO "Signing intermediate with root (policy_strict)"
    CA_DIR="$ROOT_DIR" sign_cert "intermediate" "$CONF" -batch \
      -policy policy_strict \
      -extensions v3_intermediate_ca -days 3650 -notext -md sha256 \
      -in  "$INTERMEDIATE_DIR/csr/intermediate.csr.pem" \
      -out "$INTERMEDIATE_DIR/certs/ca.cert.pem"
    chmod 444 "$INTERMEDIATE_DIR/certs/ca.cert.pem"
  fi

  log INFO "Building chain file"
  cat "$INTERMEDIATE_DIR/certs/ca.cert.pem" "$ROOT_DIR/certs/ca.cert.pem" \
    > "$INTERMEDIATE_DIR/certs/ca-chain.cert.pem"

  log INFO "Verifying intermediate -> root"
  openssl verify -CAfile "$ROOT_DIR/certs/ca.cert.pem" \
    "$INTERMEDIATE_DIR/certs/ca.cert.pem" \
    || { log ERROR "intermediate verify failed"; return 1; }
  log SUCCESS "Intermediate CA ready"
}

create_leaf() {
  local name=$LEAF_NAME
  log INFO "Creating leaf: $name"

  local key=$INTERMEDIATE_DIR/private/$name.key.pem
  local csr=$INTERMEDIATE_DIR/csr/$name.csr.pem
  local crt=$INTERMEDIATE_DIR/certs/$name.cert.pem

  gen_private_key "$key" 2048

  if [[ -f $csr ]]; then
    log WARN "leaf CSR exists, skipping"
  else
    log INFO "Generating leaf CSR"
    CA_DIR="$INTERMEDIATE_DIR" SAN="DNS:$name" openssl req -config "$CONF" -new -sha256 \
      -key "$key" -subj "$LEAF_SUBJ" -out "$csr"
  fi

  if [[ -f $crt ]]; then
    log WARN "leaf cert exists, skipping"
  else
    log INFO "Signing leaf with intermediate (policy_loose)"
    CA_DIR="$INTERMEDIATE_DIR" SAN="DNS:$name" sign_cert "leaf-$name" "$CONF" -batch \
      -policy policy_loose \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in "$csr" -out "$crt"
  fi

  log INFO "Verifying leaf -> intermediate -> root"
  openssl verify -CAfile "$INTERMEDIATE_DIR/certs/ca-chain.cert.pem" "$crt" \
    || { log ERROR "leaf verify failed"; return 1; }
  log SUCCESS "Leaf cert ready"
}

create_root
create_intermediate
create_leaf
inspect_cert "$ROOT_DIR/certs/ca.cert.pem"
inspect_cert "$INTERMEDIATE_DIR/certs/ca.cert.pem"
inspect_cert "$INTERMEDIATE_DIR/certs/$LEAF_NAME.cert.pem"
