FROM python:3.12-slim
WORKDIR /srv

# toolchain to compile the native host, removed again to keep the image lean
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# the native host source is compiled at build time; NO flag is baked in (only an in-binary
# decoy). The real flag arrives at runtime via PINAKA_FLAG and is read by the host itself.
COPY host.c .
RUN gcc -O2 -std=c11 -Wall -o /srv/host /srv/host.c && rm -f /srv/host.c

COPY validator.py .
ENV HOST_BIN=/srv/host
ENV PORT=8060
EXPOSE 8060
# player bytecode modules (player/) are NOT copied — players craft and submit their own.
CMD ["python", "validator.py"]
