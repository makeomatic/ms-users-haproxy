module.exports = {
  logger: {
    debug: true,
  },
  consul: {
    base: {
      host: 'consul',
    },
  },
  jwt: {
    stateless: {
      jwe: {
        jwk: [
          {
            default: true,
            kty: 'oct',
            use: 'enc',
            kid: 'enc-2022-04-12T07:25:52Z',
            k: 'm0kTI7Vp2Hm5A5whjrYw9V5GtvQcrZEFYQiwjXqM1A1Iy_bmYENOHAjztDEBWHx-OwpsYMJ8HT2X-iIE-u1UFQ',
            alg: 'dir',
          },
        ],
        cypher: {
          alg: 'dir',
          enc: 'A256CBC-HS512',
        },
      },
    },
  },
};
