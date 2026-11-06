# Sandbox image for attacker sessions.
#
# Ubuntu 22.04 with the GNU userland a real server has, so `ls --help`,
# `ps`, `ip` and friends behave like the Ubuntu persona instead of BusyBox.
# Containers from this image run with networking disabled; network access is
# only needed while building it.
#
# Built automatically by Doppel when missing, or manually:
#   python -m doppel.cli build-sandbox
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash coreutils findutils grep sed gawk procps psmisc iproute2 net-tools \
      iputils-ping lsof less file nano vim-tiny curl wget ca-certificates \
      python3 git zip unzip tar gzip bzip2 xz-utils cron sudo \
 && rm -rf /var/lib/apt/lists/*

# The persona's default account; other login names are added per session
RUN useradd -m -u 1000 -s /bin/bash ubuntu \
 && echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu \
 && chmod 0440 /etc/sudoers.d/ubuntu

CMD ["/bin/bash"]
