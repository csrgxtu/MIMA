FROM python:3.9

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./ab_requester.py /code/ab_requester.py

# CMD ["python", "ab_requester.py"]
