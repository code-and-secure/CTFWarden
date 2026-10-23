FROM python:3.12-alpine
RUN apk add --no-cache conntrack-tools \
 && pip install --no-cache-dir "docker>=7,<8"
WORKDIR /app
COPY ctfmon.py /app/ctfmon.py
COPY static /app/static
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/ctfmon.py"]
