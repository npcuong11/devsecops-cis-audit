
FROM python:3.11-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Cap nhat cac goi he thong
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Tao tai khoan khong co quyen Root
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Cai dat thu vien Python
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Sao chep ma nguon
COPY auditor.py main.py ./

# Phan quyen ung dung
RUN chown -R 10001:10001 /app

# Chay bang UID 10001
USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
