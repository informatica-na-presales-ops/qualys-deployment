FROM python:3.9.2-alpine3.13

COPY requirements.txt /qualys-deployment/requirements.txt
RUN /usr/local/bin/pip install --no-cache-dir --requirement /qualys-deployment/requirements.txt

ENV PYTHONUNBUFFERED="1" \
    TZ="Etc/UTC"
