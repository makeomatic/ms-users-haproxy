return {
  jwt = {
    cacheTTL = os.getenv("JWT_CACHE_TTL") or 2,
    tokenServer = os.getenv("JWT_TOKEN_SERVER_BACKEND") or "jwt-server"
  }
}
