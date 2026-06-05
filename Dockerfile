FROM python:3.11-slim

# 安装 iptables
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# iptables 操作需要 root 或 CAP_NET_ADMIN，配合 docker-compose cap_add 使用
CMD ["python", "app.py"]
