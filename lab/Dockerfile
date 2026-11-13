FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /lab
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY web.py .
USER 65534:65534
EXPOSE 8099
CMD ["python", "web.py", "--container", "--bind", "0.0.0.0", "--db-host", "db"]
