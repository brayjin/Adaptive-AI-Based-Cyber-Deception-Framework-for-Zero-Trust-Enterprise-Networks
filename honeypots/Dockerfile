FROM python:3.11-slim

WORKDIR /service
RUN groupadd --system app && useradd --system --gid app --create-home --home-dir /home/app app && install -d -o app -g app -m 700 /var/lib/honeypot
COPY service.py .
RUN chown -R app:app /service /var/lib/honeypot
USER app

EXPOSE 8080
CMD ["python", "service.py"]