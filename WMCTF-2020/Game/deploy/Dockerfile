FROM python:3.8-alpine
LABEL Description="Game" VERSION='1.0'

RUN apk update && apk add gcc g++ make openssl-dev python3-dev libffi-dev autoconf

WORKDIR /opt/game
RUN mkdir -p /opt/game

COPY task.py .
COPY secret.py .

RUN pip install pycryptodome

EXPOSE 10000
CMD ["python", "-u", "task.py"]
