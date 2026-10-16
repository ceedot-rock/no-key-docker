FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY warrant_lib.py rider_verify.py gate.py server.py ./
ENV DRY_RUN=1
EXPOSE 8000
CMD ["python", "server.py"]
