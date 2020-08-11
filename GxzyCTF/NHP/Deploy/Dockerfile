FROM python:3.7-alpine
LABEL Description="hnp" VERSION='1.0'

RUN apk update && apk add socat gcc g++ make openssl-dev python3-dev libffi-dev autoconf

WORKDIR /opt/hnp
RUN mkdir -p /opt/hnp

COPY server.py .
COPY flag.py .

RUN pip install pycryptodome

EXPOSE 10000
CMD ["socat", "TCP-LISTEN:10000,reuseaddr,nodelay,fork", "EXEC:python -u /opt/hnp/server.py"]