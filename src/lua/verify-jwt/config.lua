return {
  jwt = {
    jwksUrl = os.getenv("JWT_JWKS_URL"),
    jwksFile = os.getenv("JWT_JWKS_FILE"),
    syncInterval = os.getenv("JWT_SYNC_INTERVAL") or 300,
    cacheTTL = os.getenv("JWT_CACHE_TTL") or 10
  }
}
