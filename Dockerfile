FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py index.html ./

EXPOSE 3000

CMD ["sh", "-c", "SERVER_PORT=${PORT:-3000} python bot.py"]
