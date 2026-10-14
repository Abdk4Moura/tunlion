# A plain Debian machine with a normal user, as a first-time user would have.
FROM debian:stable-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl procps tmux less nano iproute2 unzip zip file openssh-client openssh-server sudo fuse3 \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/*
RUN useradd -m -s /bin/bash sam && mkdir -p /run/sshd
COPY tunlion /usr/local/bin/tunlion
RUN chmod 755 /usr/local/bin/tunlion
USER sam
WORKDIR /home/sam
