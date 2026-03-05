FROM python:3.12-slim@sha256:ccc7089399c8bb65dd1fb3ed6d55efa538a3f5e7fca3f5988ac3b5b87e593bf0

WORKDIR /app

COPY . /app

RUN python -m pip install -U pip setuptools wheel \
    && python -m pip install .

CMD ["python", "examples/deployment/openai_docker/app.py"]
