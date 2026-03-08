FROM python:3.12-slim

LABEL maintainer="Orchesis <orchesis@users.noreply.github.com>"
LABEL org.opencontainers.image.source="https://github.com/poushwell/orchesis"
LABEL org.opencontainers.image.description="Orchesis Security Scanner for AI Agent configs"

# Install Orchesis scanner
RUN pip install --no-cache-dir orchesis

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
