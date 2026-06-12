FROM smallstep/step-ca:latest

USER root

WORKDIR /home/step

# Create directory structure
RUN mkdir -p /home/step/config /home/step/certs /home/step/secrets /home/step/db

# Copy config
COPY step-ca/config/ca.json /home/step/config/ca.json

# Copy certificates and key (from project root context)
COPY certs/root-ca.crt /home/step/certs/root.crt
COPY certs/intermediate-step-ca.crt /home/step/certs/intermediate.crt
COPY certs/intermediate-step-ca-key.pem /home/step/secrets/intermediate-key

# Create password file and set correct ownership/permissions
RUN echo "step-ca-password" > /home/step/config/password && \
    chmod 600 /home/step/config/password && \
    chmod 400 /home/step/secrets/intermediate-key && \
    chown -R step:step /home/step

USER step

EXPOSE 8443

ENTRYPOINT ["step-ca"]
CMD ["/home/step/config/ca.json", "--password-file", "/home/step/config/password"]
