FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app
CMD ["gunicorn", "main:app", "-b", "0.0.0.0:5000"]
