# OpenClaw benchmark environment
#
# Config (openclaw.json, auth-profiles.json) is NOT baked in here.
# reset_env.sh restores configs/platforms/openclaw.json and
# configs/platforms/openclaw_auth-profiles.json before every task run.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. System dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git ca-certificates python3 python3-pip binutils libpython3.12 postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# 2. Node.js 22 (NodeSource)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# 3. OpenClaw
RUN npm install -g openclaw@2026.3.12

# 4. Build and install gog CLI (compiled binary — source is not present in the final image)
COPY tools/gogcli/gog /tmp/gog_src.py
RUN pip3 install --quiet --break-system-packages pyinstaller && \
    pyinstaller --onefile --strip --name gog /tmp/gog_src.py && \
    mv dist/gog /usr/local/bin/gog && \
    rm -rf /tmp/gog_src.py build dist gog.spec /root/.local /root/.cache
ENV GOG_ACCOUNT="alice@gmail.com"

# 5. Initialize openclaw directory structure with a throwaway key.
#    reset_env.sh will overwrite openclaw.json and auth-profiles.json
#    with the checked-in baseline configs before every task.
RUN openclaw onboard --non-interactive \
      --mode local \
      --auth-choice openai-api-key \
      --openai-api-key "placeholder" \
      --secret-input-mode plaintext \
      --gateway-port 18789 \
      --gateway-bind loopback \
      --accept-risk \
      --skip-skills \
      --daemon-runtime node \
      --skip-health

EXPOSE 18789
