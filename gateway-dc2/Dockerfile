FROM alpine:3.19
RUN apk add --no-cache openssh-server openssh-sftp-server openssh-client curl
RUN ssh-keygen -A

# Create gateway user (certificate-only auth)
RUN adduser -D gateway-user && passwd -d gateway-user

# Copy SSH config
COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]