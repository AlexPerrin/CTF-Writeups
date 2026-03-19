FROM alpine:3.14
RUN apk add --update python3 openssh \
    && mkdir -p /build

WORKDIR /build
COPY main.py .

# give hexed empty password
RUN ssh-keygen -f /etc/ssh/ssh_host_ed25519_key -t ed25519 -N ""
RUN adduser -s /build/main.py -D hexed
RUN passwd -d hexed

COPY flag.txt /
CMD /usr/sbin/sshd -D -e -o PermitEmptyPasswords=yes -o PermitRootLogin=no \
        -o HostKey=/etc/ssh/ssh_host_ed25519_key -o PrintMotd=no -o PrintLastLog=no
