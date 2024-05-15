# See: https://unbound.net/
FROM ubuntu:22.04
ARG UNBOUND_VERSION=1.17.1

RUN apt-get update && \
apt-get upgrade -y && \
apt-get install --no-install-recommends -y \
	build-essential \
	ca-certificates \
	dnsutils \
	libevent-dev \
	libpython3.10 \
	libpython3.10-dev \
	libssl-dev \
	python3.10 \
	python3-distutils \
	rsyslog \
	swig \
	vim \
	wget && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget "https://www.nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz" && \
	tar zxvf unbound*.tar.gz && \
	cd $(find . -type d -name 'unbound*') && \
	ln -s /usr/bin/python3 /usr/bin/python && \
	./configure && \
	make && \
	make install && \
	useradd unbound && \
	chown -R unbound: /usr/local/etc/unbound/ && \
	cd /opt && \
	rm -Rf /opt/unbound*

RUN apt-get purge -y build-essential \
	ca-certificates \
	libevent-dev \
	libpython3.10-dev \
	libssl-dev \
	swig \
	wget

WORKDIR /usr/local/etc/unbound
RUN mv unbound.conf unbound.conf.org
COPY unbound.conf ./
COPY helloworld.py ./

# Ready! Once in a Bash shell you can do 'unbound' then 'dig +noall +answer @127.0.0.1' to see the output of the
# Hello World Python module:
# root@nnn:/usr/local/etc/unbound#: unbound
# root@nnn:/usr/local/etc/unbound#: dig +noall +answer @127.0.0.1
# helloworld.  300 IN A 127.0.0.1
#ENTRYPOINT ["/bin/bash"]
