FROM alpine:3.19
RUN apk add --no-cache openssh-server openssh-sftp-server
RUN ssh-keygen -A

# Create test user
RUN adduser -D ssh-user && echo "ssh-user:password" | chpasswd

# Copy SSH config
COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]