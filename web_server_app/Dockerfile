FROM python:3.9

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./web_server_app.py /code/web_server_app.py

CMD ["uvicorn", "web_server_app:app", "--no-access-log", "--workers", "16", "--limit-concurrency", "1024", "--backlog", "128", "--host", "0.0.0.0", "--port", "8080"]
