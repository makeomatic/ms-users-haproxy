local keyPrefix = os.getenv("CONSUL_KEY_PREFIX") or "microfleet/ms-users/revocation-rules"

if string.match(keyPrefix, "/$") == nil then
  keyPrefix = keyPrefix .. "/"
end

return {
  consul = {
    addr = os.getenv("CONSUL_ADDR") or "consul:8500",
    syncInterval = os.getenv("CONSUL_SYNC_INTERVAL") or 300,
    keyPrefix = keyPrefix
  },
  jwt = {
    jwksUrl = os.getenv("JWT_JWKS_URL"),
    jwksFile = os.getenv("JWT_JWKS_FILE"),
    syncInterval = os.getenv("JWT_SYNC_INTERVAL") or 300,
    cacheTTL = os.getenv("JWT_CACHE_TTL") or 200
  }
}
