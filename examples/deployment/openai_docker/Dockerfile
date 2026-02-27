FROM python:3.12-slim

WORKDIR /app

COPY . /app

RUN python -m pip install -U pip setuptools wheel \
    && python -m pip install .

CMD ["python", "examples/deployment/openai_docker/app.py"]
