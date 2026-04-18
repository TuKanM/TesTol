FROM python:3.11-slim

WORKDIR /app

COPY server.py .

EXPOSE 40443

CMD ["python", "-u", "server.py"]
