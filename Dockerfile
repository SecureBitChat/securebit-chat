# SecureBit.chat is a static PWA (no backend). The committed build artifacts in
# dist/ are served as-is by nginx — matching the project's release workflow,
# where dist/ is rebuilt and committed for every release.
FROM nginx:1.27-alpine

# Replace the default nginx config with our static-serving config.
COPY deploy/nginx.conf /etc/nginx/nginx.conf

# The www.securebit.chat kill-switch worker. It lives outside the web root because
# it is deployment plumbing, not site content: the apex must never serve it as
# /sw.js, which is the real, caching worker.
COPY deploy/www-sw.js /etc/nginx/www-sw.js

# The TURN credential endpoint (POST /api/turn-credentials), run by nginx's njs
# module. The secret it signs with comes from the TURN_SECRET Fly secret.
COPY deploy/turn-credentials.js /etc/nginx/njs/turn-credentials.js

# Serve the repository (src/, assets/, libs/, dist/, config/, logo/, sw.js, ...).
COPY . /usr/share/nginx/html

# config/ice-servers.js is git-ignored (it can hold operator TURN credentials),
# so it is absent from the build context. Provide the public-STUN production
# override so the operator-override path is populated and nothing 404s.
RUN cp /usr/share/nginx/html/config/ice-servers.prod.js \
       /usr/share/nginx/html/config/ice-servers.js

# Fly.io health checks and routing target this port.
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
