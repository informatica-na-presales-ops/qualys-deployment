FROM python:3.9.5-alpine3.13

COPY requirements.txt /qualys-deployment/requirements.txt
RUN /usr/local/bin/pip install --no-cache-dir --requirement /qualys-deployment/requirements.txt

ENV APP_VERSION="2021.4" \
    PYTHONUNBUFFERED="1" \
    TZ="Etc/UTC"

COPY deploy-to-aws.py /qualys-deployment/deploy-to-aws.py
