FROM python:3.11-slim

# 安装 iptables 和编译依赖（python-iptables 需要 gcc 编译 C 扩展）
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables gcc libc6-dev libxtables-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 清理编译工具（运行时不需要）
RUN apt-get purge -y gcc libc6-dev libxtables-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 5000

# iptables 操作需要 root 或 CAP_NET_ADMIN，配合 docker-compose cap_add 使用
CMD ["python", "app.py"]
