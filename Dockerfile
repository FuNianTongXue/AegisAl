FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECFLOW_DATA_DIR=/app/data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY LICENSE NOTICE README.md ./

RUN mkdir -p /app/data

EXPOSE 18081

CMD ["uvicorn", "app.api.routes.application:app", "--host", "0.0.0.0", "--port", "18081"]
