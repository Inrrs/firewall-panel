# 防火墙面板

基于 Flask 的 iptables 规则管理面板，提供 Web 界面管理 Linux 防火墙规则。

## 功能特性

- ✅ 查看/添加/删除 iptables 规则
- ✅ 按链筛选规则（INPUT/OUTPUT/FORWARD）
- ✅ 规则搜索
- ✅ 规则备份与恢复
- ✅ 规则快照与变更检测
- ✅ 规则导出/导入（JSON格式）
- ✅ iptables规则保存/恢复
- ✅ 清除规则
- ✅ 操作日志审计
- ✅ 登录认证与会话管理
- ✅ 会话超时控制
- ✅ CSRF 防护
- ✅ 输入验证
- ✅ 登录失败锁定

## 快速开始

### 方式一：直接运行

```bash
# 克隆项目
git clone <repo-url>
cd firewall-panel

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 修改密码和密钥

# 运行（需要 root 权限）
sudo python app.py
```

### 方式二：Docker

```bash
# 配置环境变量
cp .env.example .env
# 编辑 .env 修改密码和密钥

# 构建并运行
docker-compose up -d

# 查看日志
docker-compose logs -f
```

访问 `http://localhost:5000`，使用配置的账号密码登录。

> **注意：** Docker 使用 `network_mode: host` 模式，容器共享宿主机网络，才能操作宿主机的 iptables 防火墙。

## 公网部署（Nginx 反向代理）

```nginx
server {
    listen 443 ssl;
    server_name firewall.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

公网部署时：
1. 设置 `LISTEN_HOST=127.0.0.1`（只允许本地访问，通过 Nginx 代理）
2. 设置 `HTTPS_ENABLED=1`（启用安全 Cookie 和 HSTS）
3. 设置强密码 `ADMIN_PASS`
4. 设置随机 `SECRET_KEY`

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SECRET_KEY` | Flask session 密钥 | 随机生成 |
| `ADMIN_USER` | 管理员用户名 | `admin` |
| `ADMIN_PASS` | 管理员密码 | `admin123` |
| `SESSION_TIMEOUT` | 会话超时（秒） | `1800` |
| `MAX_LOGIN_ATTEMPTS` | 登录失败锁定次数 | `5` |
| `HTTPS_ENABLED` | 启用 HTTPS 安全设置 | 空（禁用） |
| `LISTEN_HOST` | 监听地址 | `127.0.0.1` |
| `LISTEN_PORT` | 监听端口 | `5000` |

## 项目结构

```
firewall-panel/
├── app.py              # 主应用
├── requirements.txt    # Python 依赖
├── .env.example        # 环境变量示例
├── .gitignore          # Git 忽略文件
├── Dockerfile          # Docker 构建文件
├── docker-compose.yml  # Docker Compose 配置
├── templates/
│   ├── index.html      # 主页面
│   ├── login.html      # 登录页面
│   ├── logs.html       # 日志页面
│   └── import.html     # 导入页面
├── static/
│   └── style.css       # 样式文件
├── backups/            # 规则备份目录
└── snapshots/          # 规则快照目录
```

## 安全说明

⚠️ **生产环境请务必：**

1. 修改默认密码
2. 设置强随机 `SECRET_KEY`
3. 使用 HTTPS（配置反向代理）
4. 限制访问 IP
5. 定期备份规则

## 许可证

MIT License
