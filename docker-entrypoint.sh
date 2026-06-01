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

nuclei_template_dir="${ZERO_NUCLEI_TEMPLATE_DIR:-/home/zero/nuclei-templates}"
mkdir -p "$nuclei_template_dir"
chown -R zero:zero /home/zero/.config "$nuclei_template_dir" 2>/dev/null || true

if [ "${ZERO_NUCLEI_UPDATE_TEMPLATES_ON_STARTUP:-true}" = "true" ] && command -v nuclei >/dev/null 2>&1; then
  timeout "${ZERO_TOOL_TIMEOUT:-20m}" su-exec zero nuclei -update-templates -update-template-dir "$nuclei_template_dir" -silent >/dev/null 2>&1 || true
fi

exec su-exec zero zero "$@"
