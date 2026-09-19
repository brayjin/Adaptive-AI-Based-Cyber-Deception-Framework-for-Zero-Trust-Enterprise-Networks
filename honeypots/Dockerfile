FROM python:3.11-slim

WORKDIR /service
RUN groupadd --system app && useradd --system --gid app --create-home --home-dir /home/app app
COPY service.py .
RUN openssl req -x509 -newkey rsa:2048 -keyout /tmp/honeypot.key -out /tmp/honeypot.crt -days 365 -nodes -subj "/CN=localhost" && chown -R app:app /service /tmp/honeypot.key /tmp/honeypot.crt
USER app

EXPOSE 8080
CMD ["python", "service.py"]