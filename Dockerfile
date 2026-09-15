FROM python:3.12-slim-bookworm

WORKDIR /app

COPY app.py requirements.txt ./

EXPOSE 3000

RUN apt-get update && apt-get install -y --no-install-recommends libc6 libssl3 ca-certificates curl bash && rm -rf /var/lib/apt/lists/* &&\
    chmod +x app.py &&\
    pip install --no-cache-dir -r requirements.txt

CMD ["python3", "app.py"]
