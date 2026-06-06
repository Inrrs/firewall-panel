FROM python:3.11-slim

# 使用国内镜像源加速构建
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources

# 安装 iptables 和编译依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables gcc libc6-dev libxtables-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# 使用国内 pip 镜像源
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com

# 清理编译工具（运行时不需要）
RUN apt-get purge -y gcc libc6-dev libxtables-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 8901

CMD ["python", "app.py"]
