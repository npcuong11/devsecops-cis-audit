
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Cập nhật hệ điều hành
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# Tạo tài khoản không có quyền Root
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Cài thư viện
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Sao chép mã nguồn
COPY auditor.py main.py ./

# Phân quyền ứng dụng
RUN chown -R 10001:10001 /app

# Chạy bằng UID 10001
USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
