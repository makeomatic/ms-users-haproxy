FROM haproxy:2.5.1-alpine

USER root

RUN set -eux; \
  apk add --no-cache --virtual .run-deps \
    lua5.3 \
    openssl \
  ; \
	apk add --no-cache --virtual .build-deps \
    gcc \
		libc-dev \
		linux-headers \
		lua5.3-dev \
		make \
		openssl \
		openssl-dev \
		pcre2-dev \
		readline-dev \
    wget \
    unzip \
	; \
  \
  wget https://luarocks.org/releases/luarocks-3.8.0.tar.gz; \
  tar zxpf luarocks-3.8.0.tar.gz; \
  cd luarocks-3.8.0; \
  ./configure --prefix=/usr/local && make && make install; \
  \
  cd ..;\
  rm -rf ./luarocks-3.8*; \
  \
  luarocks install lua-cjson 2.1.0-1; \
  luarocks install LuaSocket; \
  luarocks install luaossl; \
  luarocks install --server=http://luarocks.org/dev lua-consul; \
  \
  apk del --no-network .build-deps;

COPY ./src /usr/local/lib/lua/5.3/

USER haproxy
