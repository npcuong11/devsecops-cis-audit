FROM python:3.11-slim-bookworm

# Cập nhật OS để không bị Trivy báo lỗi CRITICAL
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Tạo user non-root để an toàn tuyệt đối
RUN useradd -m -u 10001 appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY auditor.py main.py ./
RUN chown -R appuser:appuser /app

USER 10001
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
