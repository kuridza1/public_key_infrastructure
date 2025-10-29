ng serve --ssl true --ssl-cert ./fullchain.pem --ssl-key ./key.pem --host 0.0.0.0
docker run --rm -d -p 1025:1025 -p 8025:8025 --name mailhog mailhog/mailhog
