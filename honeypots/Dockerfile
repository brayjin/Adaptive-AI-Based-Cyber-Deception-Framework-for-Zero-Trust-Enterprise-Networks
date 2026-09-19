FROM python:3.11-slim

WORKDIR /service
COPY honeypots/service.py .

EXPOSE 8080
CMD ["python", "service.py"]