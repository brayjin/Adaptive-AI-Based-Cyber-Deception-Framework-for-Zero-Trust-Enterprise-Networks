FROM python:3.11-slim

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --create-home --home-dir /home/app app && chown -R app:app /app

COPY pyproject.toml README.md ./
COPY backend ./backend
COPY ml ./ml
COPY scripts ./scripts
COPY data/benchmark ./data/benchmark

RUN pip install --no-cache-dir --only-binary=:all: .

USER app

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]