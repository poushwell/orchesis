FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .


FROM python:3.11-slim AS runtime

WORKDIR /app

COPY --from=builder /install /usr/local
COPY examples ./examples

ENV PYTHONUNBUFFERED=1

CMD ["orchesis", "--help"]
