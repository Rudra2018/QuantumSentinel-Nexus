#!/bin/sh

# Set default port if not provided
export PORT=${PORT:-8080}

# Substitute environment variables in nginx config
envsubst '$PORT' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx
nginx -g "daemon off;"