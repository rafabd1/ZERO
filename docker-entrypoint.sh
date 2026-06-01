#!/bin/sh
set -eu

provider_config="${ZERO_SUBFINDER_PROVIDER_CONFIG:-/home/zero/.config/subfinder/provider-config.yaml}"
mkdir -p "$(dirname "$provider_config")"

if [ ! -s "$provider_config" ]; then
  {
    [ -n "${ZERO_SUBFINDER_SHODAN_API_KEY:-}" ] && printf 'shodan:\n  - "%s"\n' "$ZERO_SUBFINDER_SHODAN_API_KEY"
    [ -n "${ZERO_SUBFINDER_BEVIGIL_API_KEY:-}" ] && printf 'bevigil:\n  - "%s"\n' "$ZERO_SUBFINDER_BEVIGIL_API_KEY"
    [ -n "${ZERO_SUBFINDER_VIRUSTOTAL_API_KEY:-}" ] && printf 'virustotal:\n  - "%s"\n' "$ZERO_SUBFINDER_VIRUSTOTAL_API_KEY"
    [ -n "${ZERO_SUBFINDER_SECURITYTRAILS_API_KEY:-}" ] && printf 'securitytrails:\n  - "%s"\n' "$ZERO_SUBFINDER_SECURITYTRAILS_API_KEY"
  } > "$provider_config"
fi

exec zero "$@"
