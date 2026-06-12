FROM nginx:alpine

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy certificates (mounted at /certs in the container)
# certs are shared via Docker volumes — no COPY needed here
# The certs volume from the host certs/ directory is mounted at /certs

EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]
