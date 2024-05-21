FROM python:3.12 
RUN pip install poetry
LABEL MAINTAINER="rasafinayat@gmail.com"
WORKDIR /code
COPY ./pyproject.toml /code/
COPY ./fastapi_docker /code/fastapi_docker/
RUN poetry install
CMD ["poetry", "run", "uvicorn", "fastapi_docker.main:app", "--host", "0.0.0.0"]