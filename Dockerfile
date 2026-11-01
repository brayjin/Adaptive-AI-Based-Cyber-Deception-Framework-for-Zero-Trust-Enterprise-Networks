FROM python:3.11-slim

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --create-home --home-dir /home/app app

COPY pyproject.toml README.md ./
COPY backend ./backend
COPY ml ./ml
COPY rl ./rl
COPY federated ./federated
COPY honeypots ./honeypots
COPY scripts ./scripts
COPY data/benchmark ./data/benchmark

RUN pip install --no-cache-dir --only-binary=:all: .

RUN mkdir -p /app/data /app/ml/saved_models && chown -R app:app /app

USER app

ENV HONEYPOT_BACKEND=simulator
ENV DATABASE_URL=sqlite+aiosqlite:////data/cyber_deception.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/system/health')" || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]