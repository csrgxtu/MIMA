FROM ubuntu:20.04

WORKDIR /code
COPY ./requirements.txt /code/requirements.txt


RUN apt update
RUN apt install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt install -y python3.9 python3.9-dev
RUN apt install -y python3-pip
RUN ln -s /usr/bin/python3.9 /usr/bin/python
RUN apt install -y nginx
RUN apt install -y net-tools
RUN apt install -y libpcap0.8

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY ./http_sniffer.py /code/http_sniffer.py

COPY nginx.conf /etc/nginx/nginx.conf
ENTRYPOINT nginx -g "daemon on;" && python3 -m http.server
