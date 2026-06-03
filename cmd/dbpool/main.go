package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	upstream := strings.TrimSpace(firstNonEmpty(os.Getenv("ZERO_DATABASE_UPSTREAM_URL"), os.Getenv("ZERO_DATABASE_URL")))
	if upstream == "" {
		log.Fatal("set ZERO_DATABASE_UPSTREAM_URL or ZERO_DATABASE_URL for dbpool")
	}
	parsed, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("parse upstream database url: %v", err)
	}
	host := parsed.Hostname()
	port := firstNonEmpty(parsed.Port(), "5432")
	dbname := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if dbname == "" {
		dbname = "postgres"
	}
	dbname, _ = url.PathUnescape(dbname)
	user := ""
	password := ""
	if parsed.User != nil {
		user = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	if host == "" || user == "" {
		log.Fatal("upstream database url must include host and user")
	}

	listenAddr := firstNonEmpty(os.Getenv("ZERO_DBPOOL_LISTEN_ADDR"), "0.0.0.0")
	listenPort := firstNonEmpty(os.Getenv("ZERO_DBPOOL_LISTEN_PORT"), "6432")
	clientUser := firstNonEmpty(os.Getenv("ZERO_DBPOOL_CLIENT_USER"), "zero")
	sslMode := firstNonEmpty(parsed.Query().Get("sslmode"), os.Getenv("ZERO_DBPOOL_UPSTREAM_SSLMODE"), "require")
	defaultPoolSize := clampEnvInt("ZERO_DBPOOL_DEFAULT_POOL_SIZE", 8, 1, 64)
	reservePoolSize := clampEnvInt("ZERO_DBPOOL_RESERVE_POOL_SIZE", 2, 0, 64)
	maxClientConn := clampEnvInt("ZERO_DBPOOL_MAX_CLIENT_CONN", 500, 10, 10000)
	queryTimeout := clampEnvInt("ZERO_DBPOOL_QUERY_TIMEOUT", 0, 0, 86400)
	serverConnectTimeout := clampEnvInt("ZERO_DBPOOL_SERVER_CONNECT_TIMEOUT", 15, 1, 120)

	config := fmt.Sprintf(`[databases]
* = host=%s port=%s dbname=%s user=%s password=%s pool_mode=transaction

[pgbouncer]
listen_addr = %s
listen_port = %s
server_tls_sslmode = %s
auth_type = trust
auth_file = /tmp/zero-pgbouncer-users.txt
admin_users = %s, postgres
stats_users = %s, postgres
pool_mode = transaction
max_client_conn = %d
default_pool_size = %d
reserve_pool_size = %d
reserve_pool_timeout = 5
server_connect_timeout = %d
server_idle_timeout = 60
server_lifetime = 3600
server_reset_query = DISCARD ALL
ignore_startup_parameters = extra_float_digits
log_connections = 0
log_disconnections = 0
`, quoteKeyword(host), quoteKeyword(port), quoteKeyword(dbname), quoteKeyword(user), quoteKeyword(password), listenAddr, listenPort, sslMode, clientUser, clientUser, maxClientConn, defaultPoolSize, reservePoolSize, serverConnectTimeout)
	if queryTimeout > 0 {
		config += fmt.Sprintf("query_timeout = %d\n", queryTimeout)
	}

	if err := os.WriteFile("/tmp/zero-pgbouncer.ini", []byte(config), 0o600); err != nil {
		log.Fatalf("write pgbouncer config: %v", err)
	}
	userlist := fmt.Sprintf("%q %q\n%q %q\n", clientUser, "", "postgres", "")
	if err := os.WriteFile("/tmp/zero-pgbouncer-users.txt", []byte(userlist), 0o600); err != nil {
		log.Fatalf("write pgbouncer userlist: %v", err)
	}
	log.Printf("zero dbpool listening on %s, upstream=%s:%s/%s, default_pool_size=%d, reserve_pool_size=%d, max_client_conn=%d", net.JoinHostPort(listenAddr, listenPort), host, port, dbname, defaultPoolSize, reservePoolSize, maxClientConn)
	if err := syscall.Exec("/usr/bin/pgbouncer", []string{"pgbouncer", "/tmp/zero-pgbouncer.ini"}, os.Environ()); err != nil {
		log.Fatalf("exec pgbouncer: %v", err)
	}
}

func quoteKeyword(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func clampEnvInt(name string, fallback, minValue, maxValue int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	if parsed < minValue {
		return minValue
	}
	if maxValue > 0 && parsed > maxValue {
		return maxValue
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
