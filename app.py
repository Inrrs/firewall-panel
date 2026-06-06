import os
import re
import json
import hmac
import logging
import time
import secrets
import subprocess
from datetime import datetime
from functools import wraps
from collections import Counter

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, flash
)
from flask_wtf.csrf import CSRFProtect
import iptc

# ============ 路径配置 ============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============ 应用配置 ============
app = Flask(__name__)

# SECRET_KEY：优先使用环境变量，否则生成并持久化到文件
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    _key_file = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(_key_file):
        with open(_key_file, "r") as f:
            _secret_key = f.read().strip()
    if not _secret_key:
        _secret_key = secrets.token_hex(24)
        with open(_key_file, "w") as f:
            f.write(_secret_key)
app.secret_key = _secret_key

app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = int(os.environ.get("SESSION_TIMEOUT", 1800))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 上传文件最大 2MB
# 公网部署时启用 HTTPS 后设置此项
if os.environ.get("HTTPS_ENABLED"):
    app.config["SESSION_COOKIE_SECURE"] = True
csrf = CSRFProtect(app)

# 简单认证凭据（生产环境应使用数据库）
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")


@app.after_request
def set_security_headers(response):
    """设置安全响应头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if os.environ.get("HTTPS_ENABLED"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# 登录失败锁定配置
MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 5))
LOGIN_LOCKOUT_TIME = 300  # 锁定时间（秒）
login_attempts = {}  # {ip: {"count": 0, "last_attempt": 0, "locked_until": 0}}

# ============ 日志配置 ============
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)
logger = logging.getLogger(__name__)

# 密码变更日志（不记录明文）— 必须在 basicConfig 之后
if ADMIN_PASS == "admin123":
    logger.warning("检测到默认密码，请务必修改 ADMIN_PASS 环境变量")

# ============ 目录配置 ============
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

SNAPSHOT_DIR = os.path.join(BASE_DIR, "snapshots")
os.makedirs(SNAPSHOT_DIR, exist_ok=True)
SNAPSHOT_FILE = os.path.join(SNAPSHOT_DIR, "current_snapshot.json")

# IP 黑白名单文件
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.txt")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.txt")

# GeoIP 数据库路径
GEOIP_DB = os.environ.get("GEOIP_DB", "/usr/share/GeoIP/GeoLite2-Country.mmdb")

# GeoIP 封锁国家配置文件
GEOIP_BLOCK_FILE = os.path.join(BASE_DIR, "blocked_countries.json")

# 端口扫描检测配置
SCAN_DETECT_CHAIN = "PORTSCAN"
SCAN_DETECT_CONFIG = os.path.join(BASE_DIR, "scan_detect.json")

# DDoS 防护配置
DDOS_CHAIN = "DDOS"
DDOS_CONFIG = os.path.join(BASE_DIR, "ddos_config.json")

# 规则有效期配置
EXPIRY_FILE = os.path.join(BASE_DIR, "rule_expiry.json")

# 流量异常告警配置
TRAFFIC_ALERT_CONFIG = os.path.join(BASE_DIR, "traffic_alert.json")
TRAFFIC_SNAPSHOT_FILE = os.path.join(BASE_DIR, "traffic_snapshot.json")


# ============ 工具函数 ============

def load_ip_list(filepath):
    """加载 IP 列表文件"""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def save_ip_list(filepath, ip_list):
    """保存 IP 列表文件"""
    with open(filepath, "w", encoding="utf-8") as f:
        if ip_list:
            f.write("\n".join(ip_list) + "\n")


def load_blocked_countries():
    """加载被封锁的国家列表"""
    if not os.path.exists(GEOIP_BLOCK_FILE):
        return []
    with open(GEOIP_BLOCK_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_blocked_countries(countries):
    """保存被封锁的国家列表"""
    with open(GEOIP_BLOCK_FILE, "w", encoding="utf-8") as f:
        json.dump(countries, f, ensure_ascii=False, indent=2)


def load_json_config(filepath, default=None):
    """加载 JSON 配置文件"""
    if default is None:
        default = {}
    if not os.path.exists(filepath):
        return default
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_config(filepath, config):
    """保存 JSON 配置文件"""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def get_client_ip():
    """获取客户端真实 IP（支持反向代理）"""
    # X-Forwarded-For 格式：client, proxy1, proxy2
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("请先登录", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def validate_ip(ip_str):
    """验证 IP 地址格式"""
    if not ip_str:
        return True
    pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
    if not re.match(pattern, ip_str):
        return False
    parts = ip_str.split("/")[0].split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def validate_port(port_str):
    """验证单个端口格式"""
    if not port_str:
        return True
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False


def parse_ports(port_str):
    """解析端口字符串，支持单端口、逗号分隔、范围。返回端口列表或 None"""
    if not port_str or not port_str.strip():
        return None
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            # 端口范围: 80-90
            range_parts = part.split("-", 1)
            try:
                start = int(range_parts[0].strip())
                end = int(range_parts[1].strip())
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.extend(range(start, end + 1))
                else:
                    return None
            except ValueError:
                return None
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
                else:
                    return None
            except ValueError:
                return None
    return ports if ports else None


def validate_chain(chain):
    """验证链名称"""
    return chain in ("INPUT", "OUTPUT", "FORWARD")


def validate_protocol(protocol):
    """验证协议"""
    return protocol in ("all", "tcp", "udp", "icmp")


def validate_target(target):
    """验证动作"""
    return target in ("ACCEPT", "DROP", "REJECT")


def log_action(action, details):
    """记录操作日志"""
    user = session.get("username", "unknown")
    logger.info(f"[{user}] {action}: {details}")


# ============ iptables 操作 ============

def get_rules(chain_filter=None):
    """获取 iptables 规则列表"""
    rules = []
    try:
        table = iptc.Table(iptc.Table.FILTER)
        for chain in table.chains:
            if chain_filter and chain.name != chain_filter:
                continue
            for idx, rule in enumerate(chain.rules):
                rules.append({
                    "chain": chain.name,
                    "index": idx,
                    "protocol": rule.protocol if rule.protocol else "all",
                    "src": rule.src if rule.src else "0.0.0.0/0",
                    "dst": rule.dst if rule.dst else "0.0.0.0/0",
                    "target": rule.target.name if rule.target else "ACCEPT",
                    "dport": _get_dport(rule),
                    "sport": _get_sport(rule),
                })
    except Exception as e:
        logger.error(f"获取规则失败: {e}")
    return rules


def _get_dport(rule):
    """获取目标端口"""
    for match in rule.matches:
        if hasattr(match, "dport"):
            return match.dport
    return None


def _get_sport(rule):
    """获取源端口"""
    for match in rule.matches:
        if hasattr(match, "sport"):
            return match.sport
    return None


def add_rule(chain, protocol, src, dst, target, dport=None):
    """添加 iptables 规则"""
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain_obj = iptc.Chain(table, chain)
        rule = iptc.Rule()

        if protocol and protocol != "all":
            rule.protocol = protocol
        if src:
            rule.src = src
        if dst:
            rule.dst = dst

        rule.create_target(target)

        if dport and protocol in ("tcp", "udp"):
            match = iptc.Match(rule, protocol)
            match.dport = dport
            rule.add_match(match)

        chain_obj.insert_rule(rule)
        log_action("添加规则", f"chain={chain}, proto={protocol}, src={src}, dst={dst}, target={target}, dport={dport}")
        return True, "规则添加成功"
    except Exception as e:
        logger.error(f"添加规则失败: {e}")
        return False, "规则添加失败，请查看日志"


def delete_rule(chain, index):
    """删除指定位置的 iptables 规则"""
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain_obj = iptc.Chain(table, chain)
        rules = list(chain_obj.rules)
        if 0 <= index < len(rules):
            chain_obj.delete_rule(rules[index])
            log_action("删除规则", f"chain={chain}, index={index}")
            return True, "规则删除成功"
        return False, "规则索引无效"
    except Exception as e:
        logger.error(f"删除规则失败: {e}")
        return False, "规则删除失败，请查看日志"


BACKUP_MAX_COUNT = 50  # 最多保留备份数量


def backup_rules():
    """备份当前规则"""
    try:
        rules = get_rules()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"rules_{timestamp}.json"
        filepath = os.path.join(BACKUP_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
        log_action("备份规则", filename)

        # 清理旧备份，保留最新 N 个
        _cleanup_old_backups()

        return True, f"备份成功: {filename}"
    except Exception as e:
        logger.error(f"备份规则失败: {e}")
        return False, "备份失败，请查看日志"


def _cleanup_old_backups():
    """清理超出数量限制的旧备份"""
    try:
        files = sorted(
            [f for f in os.listdir(BACKUP_DIR)
             if f.startswith("rules_") and f.endswith(".json")],
            reverse=True
        )
        for old_file in files[BACKUP_MAX_COUNT:]:
            os.remove(os.path.join(BACKUP_DIR, old_file))
            logger.info(f"自动清理旧备份: {old_file}")
    except Exception as e:
        logger.error(f"清理旧备份失败: {e}")


def get_backups():
    """获取备份列表"""
    backups = []
    try:
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith(".json") or f.endswith(".rules"):
                filepath = os.path.join(BACKUP_DIR, f)
                size = os.path.getsize(filepath)
                backups.append({"name": f, "size": size})
    except Exception as e:
        logger.error(f"获取备份列表失败: {e}")
    return backups


def validate_filename(filename):
    """验证文件名，防止路径遍历"""
    if not filename:
        return False
    # 禁止空字节
    if "\x00" in filename:
        return False
    # 禁止路径分隔符和 ..
    if "/" in filename or "\\" in filename or ".." in filename:
        return False
    # 白名单：只允许字母、数字、下划线、连字符、点
    if not re.match(r'^[\w\-.]+$', filename):
        return False
    # 只允许合法备份文件名
    if not (filename.endswith(".json") or filename.endswith(".rules")):
        return False
    return True


def delete_backup(filename):
    """删除备份文件"""
    try:
        if not validate_filename(filename):
            return False, "无效的文件名"
        filepath = os.path.join(BACKUP_DIR, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            log_action("删除备份", filename)
            return True, "备份删除成功"
        return False, "备份文件不存在"
    except Exception as e:
        logger.error(f"删除备份失败: {e}")
        return False, "删除备份失败，请查看日志"


def get_logs(lines=100):
    """获取最近的日志"""
    try:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
            return all_lines[-lines:] if len(all_lines) > lines else all_lines
    except Exception as e:
        logger.error(f"读取日志失败: {e}")
        return []


def clear_all_rules(chain=None):
    """清除所有规则或指定链的规则"""
    try:
        table = iptc.Table(iptc.Table.FILTER)
        cleared_count = 0
        for chain_obj in table.chains:
            if chain and chain_obj.name != chain:
                continue
            rules = list(chain_obj.rules)
            for rule in rules:
                chain_obj.delete_rule(rule)
                cleared_count += 1
        log_action("清除规则", f"链={chain or '全部'}, 清除={cleared_count}条")
        return True, f"成功清除 {cleared_count} 条规则"
    except Exception as e:
        logger.error(f"清除规则失败: {e}")
        return False, "清除规则失败，请查看日志"


def restore_rules(filename, clear_first=False):
    """从备份文件恢复规则"""
    try:
        if not validate_filename(filename):
            return False, "无效的文件名"
        filepath = os.path.join(BACKUP_DIR, filename)
        if not os.path.exists(filepath):
            return False, "备份文件不存在"

        with open(filepath, "r", encoding="utf-8") as f:
            rules_data = json.load(f)

        if not isinstance(rules_data, list):
            return False, "备份文件格式错误"

        # 如果选择先清除现有规则
        if clear_first:
            success, msg = clear_all_rules()
            if not success:
                return False, msg

        restored_count = 0
        for rule_data in rules_data:
            if not isinstance(rule_data, dict):
                continue
            chain = rule_data.get("chain", "INPUT")
            protocol = rule_data.get("protocol", "all")
            src = rule_data.get("src", "")
            dst = rule_data.get("dst", "")
            target = rule_data.get("target", "ACCEPT")
            dport = rule_data.get("dport")

            success, _ = add_rule(chain, protocol, src, dst, target, dport)
            if success:
                restored_count += 1

        log_action("恢复规则", f"文件={filename}, 恢复={restored_count}条, 先清除={clear_first}")
        return True, f"成功恢复 {restored_count} 条规则"
    except Exception as e:
        logger.error(f"恢复规则失败: {e}")
        return False, "恢复规则失败，请查看日志"


def save_snapshot():
    """保存当前规则快照"""
    try:
        rules = get_rules()
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "rules": rules
        }
        with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)
        log_action("保存规则快照", f"规则数={len(rules)}")
        return True, f"快照保存成功，共 {len(rules)} 条规则"
    except Exception as e:
        logger.error(f"保存快照失败: {e}")
        return False, "保存快照失败，请查看日志"


def load_snapshot():
    """加载上次保存的规则快照"""
    try:
        if not os.path.exists(SNAPSHOT_FILE):
            return None
        with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"加载快照失败: {e}")
        return None


def detect_changes():
    """检测当前规则与快照的差异"""
    try:
        snapshot = load_snapshot()
        if not snapshot:
            return None, "没有保存的规则快照，请先保存快照"

        current_rules = get_rules()
        snapshot_rules = snapshot.get("rules", [])

        # 规则指纹：仅含内容，不含索引（避免顺序变化误报）
        def rule_fingerprint(rule):
            return f"{rule['chain']}|{rule['protocol']}|{rule['src']}|{rule['dst']}|{rule['target']}|{rule.get('dport', '')}|{rule.get('sport', '')}"

        # 用 Counter 处理重复规则
        snapshot_counter = Counter(rule_fingerprint(r) for r in snapshot_rules)
        current_counter = Counter(rule_fingerprint(r) for r in current_rules)

        # 找出新增和删除的指纹
        added_fps = current_counter - snapshot_counter  # current 中多出的
        deleted_fps = snapshot_counter - current_counter  # snapshot 中多出的

        # 从规则列表中提取对应的规则（保留第一条匹配的）
        def find_rules_by_fingerprints(rules, target_fps):
            result = []
            seen = Counter()
            for rule in rules:
                fp = rule_fingerprint(rule)
                if fp in target_fps and seen[fp] < target_fps[fp]:
                    result.append(rule)
                    seen[fp] += 1
            return result

        added = find_rules_by_fingerprints(current_rules, added_fps)
        deleted = find_rules_by_fingerprints(snapshot_rules, deleted_fps)

        changes = {
            "snapshot_time": snapshot.get("timestamp", "未知"),
            "snapshot_count": len(snapshot_rules),
            "current_count": len(current_rules),
            "added": added,
            "deleted": deleted,
            "has_changes": len(added) > 0 or len(deleted) > 0
        }

        return changes, "检测完成"
    except Exception as e:
        logger.error(f"检测变更失败: {e}")
        return None, "检测变更失败，请查看日志"


def check_login_attempts(ip):
    """检查登录失败锁定状态"""
    now = time.time()

    # 清理过期记录（超过锁定时间2倍的记录）
    expired_ips = [k for k, v in login_attempts.items()
                   if v.get("last_attempt", 0) + LOGIN_LOCKOUT_TIME * 2 < now]
    for k in expired_ips:
        del login_attempts[k]

    if ip in login_attempts:
        attempts = login_attempts[ip]
        # 检查是否在锁定期内
        if attempts.get("locked_until", 0) > now:
            remaining = int(attempts["locked_until"] - now)
            return False, f"账号已锁定，请 {remaining} 秒后重试"
        # 检查是否超过锁定时间，重置计数
        if attempts.get("last_attempt", 0) + LOGIN_LOCKOUT_TIME < now:
            login_attempts[ip] = {"count": 0, "last_attempt": now, "locked_until": 0}
    return True, ""


def record_login_attempt(ip, success):
    """记录登录尝试"""
    now = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = {"count": 0, "last_attempt": now, "locked_until": 0}

    if success:
        login_attempts[ip] = {"count": 0, "last_attempt": now, "locked_until": 0}
    else:
        login_attempts[ip]["count"] += 1
        login_attempts[ip]["last_attempt"] = now
        if login_attempts[ip]["count"] >= MAX_LOGIN_ATTEMPTS:
            login_attempts[ip]["locked_until"] = now + LOGIN_LOCKOUT_TIME
            logger.warning(f"IP {ip} 登录失败次数过多，已锁定 {LOGIN_LOCKOUT_TIME} 秒")


# ============ 路由 ============

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = get_client_ip()
        allowed, lock_msg = check_login_attempts(ip)
        if not allowed:
            flash(lock_msg, "danger")
            return render_template("login.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if hmac.compare_digest(username, ADMIN_USER) and hmac.compare_digest(password, ADMIN_PASS):
            record_login_attempt(ip, True)
            session["logged_in"] = True
            session["username"] = username
            session.permanent = True
            flash("登录成功", "success")
            log_action("用户登录", f"IP={ip}")
            return redirect(url_for("index"))
        else:
            record_login_attempt(ip, False)
            remaining = MAX_LOGIN_ATTEMPTS - login_attempts.get(ip, {}).get("count", 0)
            if remaining > 0:
                flash(f"用户名或密码错误（剩余 {remaining} 次尝试机会）", "danger")
            else:
                flash("用户名或密码错误", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("已退出登录", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    chain_filter = request.args.get("chain", "")
    search = request.args.get("search", "").strip()
    rules = get_rules(chain_filter or None)

    # 搜索过滤
    if search:
        search_lower = search.lower()
        rules = [r for r in rules if
                 search_lower in r.get("chain", "").lower() or
                 search_lower in r.get("protocol", "").lower() or
                 search_lower in r.get("src", "").lower() or
                 search_lower in r.get("dst", "").lower() or
                 search_lower in r.get("target", "").lower() or
                 search_lower in str(r.get("dport", ""))]

    backups = get_backups()
    return render_template("index.html", rules=rules, chain_filter=chain_filter, backups=backups, search=search)


@app.route("/add", methods=["POST"])
@login_required
def add():
    chain = "INPUT"  # 默认使用 INPUT 链
    protocol = request.form.get("protocol", "tcp")
    src = request.form.get("src", "").strip()
    dst = request.form.get("dst", "").strip()
    target = request.form.get("target", "ACCEPT")
    dport_str = request.form.get("dport", "").strip()

    # 输入验证
    errors = []
    if not validate_protocol(protocol):
        errors.append("无效的协议")
    if not validate_target(target):
        errors.append("无效的动作")
    if src and not validate_ip(src):
        errors.append("源地址格式无效")
    if dst and not validate_ip(dst):
        errors.append("目标地址格式无效")

    # 解析批量端口
    ports = parse_ports(dport_str)
    if dport_str and ports is None:
        errors.append("端口格式无效，支持: 80 / 80,443,8080 / 8000-8100")

    if errors:
        for err in errors:
            flash(err, "danger")
        return redirect(url_for("index"))

    # 批量添加规则
    if ports:
        success_count = 0
        fail_count = 0
        for port in ports:
            success, _ = add_rule(chain, protocol, src, dst, target, str(port))
            if success:
                success_count += 1
            else:
                fail_count += 1
        if success_count > 0:
            flash(f"成功添加 {success_count} 条规则" + (f"，{fail_count} 条失败" if fail_count else ""), "success")
        else:
            flash("规则添加失败，请查看日志", "danger")
    else:
        # 无端口，添加单条规则
        success, msg = add_rule(chain, protocol, src, dst, target, None)
        flash(msg, "success" if success else "danger")

    return redirect(url_for("index"))


@app.route("/delete/<chain>/<int:index>", methods=["POST"])
@login_required
def delete(chain, index):
    if not validate_chain(chain):
        flash("无效的链名称", "danger")
        return redirect(url_for("index"))

    success, msg = delete_rule(chain, index)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("index"))


@app.route("/backup", methods=["POST"])
@login_required
def backup():
    success, msg = backup_rules()
    flash(msg, "success" if success else "danger")
    return redirect(url_for("index"))


@app.route("/restore/<filename>", methods=["POST"])
@login_required
def restore(filename):
    clear_first = request.form.get("clear_first") == "on"
    success, msg = restore_rules(filename, clear_first)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("index"))


@app.route("/snapshot", methods=["POST"])
@login_required
def snapshot():
    success, msg = save_snapshot()
    flash(msg, "success" if success else "danger")
    return redirect(url_for("index"))


@app.route("/detect")
@login_required
def detect():
    changes, msg = detect_changes()
    if not changes:
        flash(msg, "warning")
    backups = get_backups()
    # detect_changes() 内部已调用 get_rules()，这里直接用变更结果中的规则
    # 如果有变更，显示当前规则；否则显示快照规则用于对比
    rules = get_rules(request.args.get("chain", "") or None)
    return render_template("index.html",
                         rules=rules,
                         chain_filter=request.args.get("chain", ""),
                         changes=changes,
                         backups=backups,
                         search="")


@app.route("/api/rules")
@login_required
def api_rules():
    chain_filter = request.args.get("chain", "")
    rules = get_rules(chain_filter or None)
    return jsonify(rules)


@app.route("/api/snapshot")
@login_required
def api_snapshot():
    """获取规则快照"""
    snapshot = load_snapshot()
    if snapshot:
        return jsonify(snapshot)
    return jsonify({"error": "没有保存的快照"}), 404


@app.route("/api/detect")
@login_required
def api_detect():
    """检测规则变更"""
    changes, msg = detect_changes()
    if changes:
        return jsonify(changes)
    return jsonify({"error": msg}), 400


@app.route("/backup/delete/<filename>", methods=["POST"])
@login_required
def delete_backup_file(filename):
    """删除备份文件"""
    success, msg = delete_backup(filename)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("index"))


@app.route("/logs")
@login_required
def logs():
    """查看日志"""
    lines = request.args.get("lines", 100, type=int)
    lines = min(max(lines, 10), 1000)  # 限制 10-1000 行
    log_lines = get_logs(lines)
    return render_template("logs.html", log_lines=log_lines, lines=lines)


@app.route("/clear", methods=["POST"])
@login_required
def clear():
    """清除规则"""
    chain = request.form.get("chain", "")
    if chain and not validate_chain(chain):
        flash("无效的链名称", "danger")
        return redirect(url_for("index"))
    success, msg = clear_all_rules(chain or None)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("index"))


@app.route("/save-rules", methods=["POST"])
@login_required
def save_rules():
    """保存当前规则到系统（iptables-save）"""
    try:
        result = subprocess.run(["iptables-save"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"iptables_{timestamp}.rules"
            filepath = os.path.join(BACKUP_DIR, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            log_action("保存iptables规则", filename)
            flash(f"规则已保存: {filename}", "success")
        else:
            logger.error(f"iptables-save 失败: {result.stderr}")
            flash("保存失败，请查看日志", "danger")
    except subprocess.TimeoutExpired:
        flash("保存超时", "danger")
    except Exception as e:
        logger.error(f"保存iptables规则失败: {e}")
        flash("保存失败，请查看日志", "danger")
    return redirect(url_for("index"))


@app.route("/export")
@login_required
def export():
    """导出当前规则为JSON"""
    try:
        rules = get_rules()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"rules_export_{timestamp}.json"
        response = jsonify(rules)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "application/json"
        log_action("导出规则", f"规则数={len(rules)}")
        return response
    except Exception as e:
        logger.error(f"导出规则失败: {e}")
        flash("导出失败，请查看日志", "danger")
        return redirect(url_for("index"))


@app.route("/import", methods=["GET", "POST"])
@login_required
def import_rules():
    """导入规则"""
    if request.method == "POST":
        if "file" not in request.files:
            flash("没有选择文件", "danger")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("没有选择文件", "danger")
            return redirect(request.url)
        if file and file.filename.endswith(".json"):
            try:
                clear_first = request.form.get("clear_first") == "on"
                if clear_first:
                    success, msg = clear_all_rules()
                    if not success:
                        flash(msg, "danger")
                        return redirect(url_for("index"))

                rules_data = json.load(file)
                if not isinstance(rules_data, list):
                    flash("JSON文件格式错误，需要规则数组", "danger")
                    return redirect(url_for("index"))

                imported_count = 0
                for rule_data in rules_data:
                    if not isinstance(rule_data, dict):
                        continue
                    chain = rule_data.get("chain", "INPUT")
                    protocol = rule_data.get("protocol", "all")
                    src = rule_data.get("src", "")
                    dst = rule_data.get("dst", "")
                    target = rule_data.get("target", "ACCEPT")
                    dport = rule_data.get("dport")

                    # 验证字段合法性
                    if not validate_chain(chain) or not validate_protocol(protocol) or not validate_target(target):
                        continue
                    if src and not validate_ip(src):
                        continue
                    if dst and not validate_ip(dst):
                        continue
                    if dport and not validate_port(str(dport)):
                        continue

                    success, _ = add_rule(chain, protocol, src, dst, target, str(dport) if dport else None)
                    if success:
                        imported_count += 1

                log_action("导入规则", f"文件={file.filename}, 导入={imported_count}条, 先清除={clear_first}")
                flash(f"成功导入 {imported_count} 条规则", "success")
            except json.JSONDecodeError:
                flash("JSON文件格式错误", "danger")
            except Exception as e:
                logger.error(f"导入规则失败: {e}")
                flash("导入失败，请查看日志", "danger")
        else:
            flash("请上传JSON文件", "danger")
        return redirect(url_for("index"))
    return render_template("import.html")


@app.route("/restore-rules/<filename>", methods=["POST"])
@login_required
def restore_iptables_rules(filename):
    """从系统规则文件恢复"""
    try:
        if not validate_filename(filename):
            flash("无效的文件名", "danger")
            return redirect(url_for("index"))
        filepath = os.path.join(BACKUP_DIR, filename)
        if not os.path.exists(filepath):
            flash("规则文件不存在", "danger")
            return redirect(url_for("index"))

        result = subprocess.run(
            ["iptables-restore", filepath],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log_action("恢复iptables规则", filename)
            flash("规则恢复成功", "success")
        else:
            logger.error(f"iptables-restore 失败: {result.stderr}")
            flash("恢复失败，请查看日志", "danger")
    except subprocess.TimeoutExpired:
        flash("恢复超时", "danger")
    except Exception as e:
        logger.error(f"恢复iptables规则失败: {e}")
        flash("恢复失败，请查看日志", "danger")
    return redirect(url_for("index"))


# ============ 新功能路由 ============

# ---------- IP 黑白名单 ----------
@app.route("/blacklist")
@login_required
def blacklist():
    """IP 黑白名单页面"""
    return render_template("blacklist.html",
                           blacklist=load_ip_list(BLACKLIST_FILE),
                           whitelist=load_ip_list(WHITELIST_FILE))


@app.route("/blacklist/add", methods=["POST"])
@login_required
def blacklist_add():
    ip = request.form.get("ip", "").strip()
    if not validate_ip(ip):
        flash("无效的 IP 地址", "danger")
        return redirect(url_for("blacklist"))
    lst = load_ip_list(BLACKLIST_FILE)
    if ip not in lst:
        lst.append(ip)
        save_ip_list(BLACKLIST_FILE, lst)
        log_action("添加黑名单IP", ip)
        flash(f"已添加 {ip} 到黑名单", "success")
    else:
        flash(f"{ip} 已在黑名单中", "warning")
    return redirect(url_for("blacklist"))


@app.route("/blacklist/delete", methods=["POST"])
@login_required
def blacklist_delete():
    ip = request.form.get("ip", "").strip()
    lst = load_ip_list(BLACKLIST_FILE)
    if ip in lst:
        lst.remove(ip)
        save_ip_list(BLACKLIST_FILE, lst)
        log_action("删除黑名单IP", ip)
        flash(f"已从黑名单移除 {ip}", "success")
    return redirect(url_for("blacklist"))


@app.route("/whitelist/add", methods=["POST"])
@login_required
def whitelist_add():
    ip = request.form.get("ip", "").strip()
    if not validate_ip(ip):
        flash("无效的 IP 地址", "danger")
        return redirect(url_for("blacklist"))
    lst = load_ip_list(WHITELIST_FILE)
    if ip not in lst:
        lst.append(ip)
        save_ip_list(WHITELIST_FILE, lst)
        log_action("添加白名单IP", ip)
        flash(f"已添加 {ip} 到白名单", "success")
    else:
        flash(f"{ip} 已在白名单中", "warning")
    return redirect(url_for("blacklist"))


@app.route("/whitelist/delete", methods=["POST"])
@login_required
def whitelist_delete():
    ip = request.form.get("ip", "").strip()
    lst = load_ip_list(WHITELIST_FILE)
    if ip in lst:
        lst.remove(ip)
        save_ip_list(WHITELIST_FILE, lst)
        log_action("删除白名单IP", ip)
        flash(f"已从白名单移除 {ip}", "success")
    return redirect(url_for("blacklist"))


# ---------- 实时连接查看 ----------
def get_connections():
    """从 /proc/net/tcp 读取当前 TCP 连接"""
    connections = []
    state_map = {
        "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
        "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
        "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
        "0A": "LISTEN", "0B": "CLOSING"
    }

    def parse_addr(hex_addr):
        ip_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        if len(ip_hex) == 8:  # IPv4
            ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -1, -2))
        else:  # IPv6
            ip = ip_hex
        return ip, port

    try:
        for proto_file, proto_name in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")]:
            if not os.path.exists(proto_file):
                continue
            with open(proto_file, "r") as f:
                lines = f.readlines()[1:]  # 跳过表头
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                remote = parts[2]
                state_hex = parts[3]

                local_ip, local_port = parse_addr(local)
                remote_ip, remote_port = parse_addr(remote)
                state = state_map.get(state_hex, state_hex)

                connections.append({
                    "protocol": proto_name,
                    "local": f"{local_ip}:{local_port}",
                    "remote": f"{remote_ip}:{remote_port}",
                    "state": state
                })
    except Exception as e:
        logger.error(f"读取连接信息失败: {e}")
    return connections


@app.route("/connections")
@login_required
def connections():
    """实时连接查看页面"""
    return render_template("connections.html")


@app.route("/api/connections")
@login_required
def api_connections():
    """API: 获取当前连接"""
    conns = get_connections()
    # 过滤参数
    state_filter = request.args.get("state", "")
    if state_filter:
        conns = [c for c in conns if c["state"] == state_filter]
    return jsonify(conns)


# ---------- 流量监控 ----------
def get_traffic_stats():
    """从 /proc/net/dev 读取网卡流量统计"""
    stats = []
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]  # 跳过前两行表头
        for line in lines:
            parts = line.split()
            if len(parts) < 17:
                continue
            iface = parts[0].rstrip(":")
            if iface == "lo":  # 跳过回环
                continue
            stats.append({
                "interface": iface,
                "rx_bytes": int(parts[1]),
                "rx_packets": int(parts[2]),
                "rx_errors": int(parts[3]),
                "rx_drops": int(parts[4]),
                "tx_bytes": int(parts[9]),
                "tx_packets": int(parts[10]),
                "tx_errors": int(parts[11]),
                "tx_drops": int(parts[12]),
            })
    except Exception as e:
        logger.error(f"读取流量统计失败: {e}")
    return stats


@app.route("/traffic")
@login_required
def traffic():
    """流量监控页面"""
    return render_template("traffic.html")


@app.route("/api/traffic")
@login_required
def api_traffic():
    """API: 获取流量统计"""
    return jsonify(get_traffic_stats())


# ---------- 地区封锁 (GeoIP) ----------
# 常见国家/地区代码
COUNTRY_CODES = {
    "CN": "中国", "US": "美国", "RU": "俄罗斯", "JP": "日本",
    "KR": "韩国", "DE": "德国", "GB": "英国", "FR": "法国",
    "IN": "印度", "BR": "巴西", "AU": "澳大利亚", "CA": "加拿大",
    "NL": "荷兰", "SG": "新加坡", "TW": "中国台湾", "HK": "中国香港",
    "UA": "乌克兰", "VN": "越南", "TH": "泰国", "ID": "印度尼西亚",
}


def lookup_country(ip):
    """查询 IP 所属国家（使用 geoiplookup 命令行工具）"""
    try:
        result = subprocess.run(
            ["geoiplookup", ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and ":" in result.stdout:
            # 输出格式: GeoIP Country Edition: US, United States
            code = result.stdout.split(":")[1].strip().split(",")[0].strip()
            return code
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # 回退：尝试 Python geoip2 库
    try:
        import geoip2.database
        reader = geoip2.database.Reader(GEOIP_DB)
        response = reader.country(ip)
        reader.close()
        return response.country.iso_code
    except Exception:
        pass
    return None


@app.route("/geoip")
@login_required
def geoip():
    """地区封锁页面"""
    return render_template("geoip.html",
                           blocked_countries=load_blocked_countries(),
                           country_codes=COUNTRY_CODES)


@app.route("/geoip/block", methods=["POST"])
@login_required
def geoip_block():
    """封锁指定国家"""
    code = request.form.get("code", "").upper().strip()
    if code not in COUNTRY_CODES:
        flash("无效的国家代码", "danger")
        return redirect(url_for("geoip"))
    blocked = load_blocked_countries()
    if code not in blocked:
        blocked.append(code)
        save_blocked_countries(blocked)
        log_action("封锁国家", f"{code} ({COUNTRY_CODES[code]})")
        flash(f"已封锁 {COUNTRY_CODES[code]} ({code})", "success")
    else:
        flash(f"{COUNTRY_CODES[code]} 已在封锁列表中", "warning")
    return redirect(url_for("geoip"))


@app.route("/geoip/unblock", methods=["POST"])
@login_required
def geoip_unblock():
    """解除国家封锁"""
    code = request.form.get("code", "").upper().strip()
    blocked = load_blocked_countries()
    if code in blocked:
        blocked.remove(code)
        save_blocked_countries(blocked)
        log_action("解除国家封锁", code)
        flash(f"已解除 {code} 的封锁", "success")
    return redirect(url_for("geoip"))


@app.route("/api/geoip/lookup", methods=["POST"])
@login_required
def api_geoip_lookup():
    """API: 查询 IP 所属国家"""
    ip = request.json.get("ip", "") if request.is_json else request.form.get("ip", "")
    if not validate_ip(ip):
        return jsonify({"error": "无效的 IP 地址"}), 400
    code = lookup_country(ip)
    country = COUNTRY_CODES.get(code, code or "未知")
    return jsonify({"ip": ip, "country_code": code, "country": country})


# ---------- 端口扫描检测 ----------
def get_scan_detect_status():
    """获取端口扫描检测状态"""
    config = load_json_config(SCAN_DETECT_CONFIG, {"enabled": False, "max_hits": 10, "interval": 60})
    # 检查 iptables 中是否已有 PORTSCAN 链
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain_exists = any(c.name == SCAN_DETECT_CHAIN for c in table.chains)
        config["active"] = chain_exists
    except Exception:
        config["active"] = False
    return config


def enable_scan_detect(max_hits=10, interval=60):
    """启用端口扫描检测（使用 iptables recent 模块）"""
    try:
        # 创建自定义链
        subprocess.run(["iptables", "-N", SCAN_DETECT_CHAIN], capture_output=True, timeout=10)
    except Exception:
        pass  # 链可能已存在

    try:
        # 清空链
        subprocess.run(["iptables", "-F", SCAN_DETECT_CHAIN], capture_output=True, timeout=10)

        # 规则：记录新连接到 recent 列表
        subprocess.run([
            "iptables", "-A", SCAN_DETECT_CHAIN,
            "-p", "tcp", "--syn",
            "-m", "recent", "--name", "portscan", "--set", "--rsource"
        ], capture_output=True, timeout=10)

        # 规则：如果在 interval 秒内超过 max_hits 次新连接，则 DROP
        subprocess.run([
            "iptables", "-A", SCAN_DETECT_CHAIN,
            "-p", "tcp", "--syn",
            "-m", "recent", "--name", "portscan", "--update",
            "--seconds", str(interval), "--hitcount", str(max_hits),
            "-j", "DROP"
        ], capture_output=True, timeout=10)

        # 规则：其余放行
        subprocess.run([
            "iptables", "-A", SCAN_DETECT_CHAIN, "-j", "RETURN"
        ], capture_output=True, timeout=10)

        # 在 INPUT 链头部插入跳转规则
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-j", SCAN_DETECT_CHAIN
        ], capture_output=True, timeout=10)

        config = {"enabled": True, "max_hits": max_hits, "interval": interval}
        save_json_config(SCAN_DETECT_CONFIG, config)
        log_action("启用端口扫描检测", f"max_hits={max_hits}, interval={interval}")
        return True, "端口扫描检测已启用"
    except Exception as e:
        logger.error(f"启用端口扫描检测失败: {e}")
        return False, "启用失败，请查看日志"


def disable_scan_detect():
    """禁用端口扫描检测"""
    try:
        # 循环移除 INPUT 链中所有跳转到 PORTSCAN 的规则
        while True:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-j", SCAN_DETECT_CHAIN],
                capture_output=True, timeout=10
            )
            if result.returncode != 0:
                break
        # 清空并删除自定义链
        subprocess.run(["iptables", "-F", SCAN_DETECT_CHAIN], capture_output=True, timeout=10)
        subprocess.run(["iptables", "-X", SCAN_DETECT_CHAIN], capture_output=True, timeout=10)
    except Exception:
        pass

    config = {"enabled": False, "max_hits": 10, "interval": 60}
    save_json_config(SCAN_DETECT_CONFIG, config)
    log_action("禁用端口扫描检测", "")
    return True, "端口扫描检测已禁用"


@app.route("/scan-detect")
@login_required
def scan_detect():
    """端口扫描检测页面"""
    status = get_scan_detect_status()
    return render_template("scan_detect.html", status=status)


@app.route("/scan-detect/enable", methods=["POST"])
@login_required
def scan_detect_enable():
    max_hits = request.form.get("max_hits", 10, type=int)
    interval = request.form.get("interval", 60, type=int)
    max_hits = max(3, min(max_hits, 100))
    interval = max(10, min(interval, 600))
    success, msg = enable_scan_detect(max_hits, interval)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("scan_detect"))


@app.route("/scan-detect/disable", methods=["POST"])
@login_required
def scan_detect_disable():
    success, msg = disable_scan_detect()
    flash(msg, "success" if success else "danger")
    return redirect(url_for("scan_detect"))


# ---------- DDoS 防护 ----------
def get_ddos_status():
    """获取 DDoS 防护状态"""
    config = load_json_config(DDOS_CONFIG, {
        "enabled": False, "connlimit": 50, "rate_limit": "100/minute"
    })
    try:
        table = iptc.Table(iptc.Table.FILTER)
        chain_exists = any(c.name == DDOS_CHAIN for c in table.chains)
        config["active"] = chain_exists
    except Exception:
        config["active"] = False
    return config


def enable_ddos(connlimit=50, rate_limit="100/minute"):
    """启用 DDoS 防护"""
    try:
        subprocess.run(["iptables", "-N", DDOS_CHAIN], capture_output=True, timeout=10)
    except Exception:
        pass

    try:
        subprocess.run(["iptables", "-F", DDOS_CHAIN], capture_output=True, timeout=10)

        # 限制单 IP 并发连接数
        subprocess.run([
            "iptables", "-A", DDOS_CHAIN,
            "-p", "tcp", "--syn",
            "-m", "connlimit", "--connlimit-above", str(connlimit),
            "-j", "DROP"
        ], capture_output=True, timeout=10)

        # 限制新建连接速率（使用 limit 模块）
        parts = rate_limit.split("/")
        if len(parts) == 2:
            rate_val = parts[0]
            rate_unit = parts[1]
            subprocess.run([
                "iptables", "-A", DDOS_CHAIN,
                "-p", "tcp", "--syn",
                "-m", "limit", "--limit", f"{rate_val}/{rate_unit}",
                "--limit-burst", str(int(rate_val) * 2),
                "-j", "RETURN"
            ], capture_output=True, timeout=10)
            # 超过速率的包 DROP
            subprocess.run([
                "iptables", "-A", DDOS_CHAIN,
                "-p", "tcp", "--syn",
                "-j", "DROP"
            ], capture_output=True, timeout=10)

        # 非 SYN 包放行
        subprocess.run([
            "iptables", "-A", DDOS_CHAIN, "-j", "RETURN"
        ], capture_output=True, timeout=10)

        # 在 INPUT 链头部插入
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-j", DDOS_CHAIN
        ], capture_output=True, timeout=10)

        config = {"enabled": True, "connlimit": connlimit, "rate_limit": rate_limit}
        save_json_config(DDOS_CONFIG, config)
        log_action("启用DDoS防护", f"connlimit={connlimit}, rate={rate_limit}")
        return True, "DDoS 防护已启用"
    except Exception as e:
        logger.error(f"启用DDoS防护失败: {e}")
        return False, "启用失败，请查看日志"


def disable_ddos():
    """禁用 DDoS 防护"""
    try:
        # 循环移除 INPUT 链中所有跳转到 DDOS 的规则
        while True:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-j", DDOS_CHAIN],
                capture_output=True, timeout=10
            )
            if result.returncode != 0:
                break
        subprocess.run(["iptables", "-F", DDOS_CHAIN], capture_output=True, timeout=10)
        subprocess.run(["iptables", "-X", DDOS_CHAIN], capture_output=True, timeout=10)
    except Exception:
        pass

    config = {"enabled": False, "connlimit": 50, "rate_limit": "100/minute"}
    save_json_config(DDOS_CONFIG, config)
    log_action("禁用DDoS防护", "")
    return True, "DDoS 防护已禁用"


@app.route("/ddos")
@login_required
def ddos():
    """DDoS 防护页面"""
    status = get_ddos_status()
    return render_template("ddos.html", status=status)


@app.route("/ddos/enable", methods=["POST"])
@login_required
def ddos_enable():
    connlimit = request.form.get("connlimit", 50, type=int)
    rate_limit = request.form.get("rate_limit", "100/minute").strip()
    connlimit = max(10, min(connlimit, 1000))
    # 验证 rate_limit 格式
    if not re.match(r'^\d+/(second|minute|hour|day)$', rate_limit):
        rate_limit = "100/minute"
    success, msg = enable_ddos(connlimit, rate_limit)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("ddos"))


@app.route("/ddos/disable", methods=["POST"])
@login_required
def ddos_disable():
    success, msg = disable_ddos()
    flash(msg, "success" if success else "danger")
    return redirect(url_for("ddos"))


# ============ 规则冲突检测 ============

def detect_conflicts():
    """检测重复和矛盾的规则"""
    rules = get_rules()
    conflicts = []
    seen = {}  # 指纹 -> 第一次出现的索引

    def rule_match_key(rule):
        """匹配条件的指纹（不含 target）"""
        return f"{rule['chain']}|{rule['protocol']}|{rule['src']}|{rule['dst']}|{rule.get('dport', '')}"

    for idx, rule in enumerate(rules):
        key = rule_match_key(rule)
        if key in seen:
            first_idx, first_rule = seen[key]
            if first_rule["target"] == rule["target"]:
                conflicts.append({
                    "type": "duplicate",
                    "rule1": first_rule,
                    "rule1_idx": first_idx,
                    "rule2": rule,
                    "rule2_idx": idx,
                    "message": f"重复规则：第 {first_idx + 1} 条与第 {idx + 1} 条完全相同"
                })
            else:
                conflicts.append({
                    "type": "contradict",
                    "rule1": first_rule,
                    "rule1_idx": first_idx,
                    "rule2": rule,
                    "rule2_idx": idx,
                    "message": f"矛盾规则：第 {first_idx + 1} 条 ({first_rule['target']}) 与第 {idx + 1} 条 ({rule['target']}) 动作冲突"
                })
        else:
            seen[key] = (idx, rule)

    return conflicts


@app.route("/conflicts")
@login_required
def conflicts():
    """规则冲突检测页面"""
    conflict_list = detect_conflicts()
    return render_template("conflicts.html", conflicts=conflict_list)


# ============ 规则有效期 ============

def load_expiry():
    """加载规则过期配置 {规则指纹: 过期时间戳}"""
    return load_json_config(EXPIRY_FILE, {})


def save_expiry(data):
    """保存规则过期配置"""
    save_json_config(EXPIRY_FILE, data)


def rule_fingerprint_full(rule):
    """规则完整指纹"""
    return f"{rule['chain']}|{rule['protocol']}|{rule['src']}|{rule['dst']}|{rule['target']}|{rule.get('dport', '')}"


def cleanup_expired_rules():
    """清理已过期的规则"""
    expiry = load_expiry()
    now = time.time()
    expired_keys = [k for k, v in expiry.items() if v <= now]
    if not expired_keys:
        return 0

    # 找到并删除过期规则
    rules = get_rules()
    removed = 0
    for rule in rules:
        fp = rule_fingerprint_full(rule)
        if fp in expired_keys:
            success, _ = delete_rule(rule["chain"], rule["index"])
            if success:
                removed += 1
                log_action("规则自动过期", fp)
                del expiry[fp]

    save_expiry(expiry)
    return removed


@app.route("/expiry")
@login_required
def expiry_page():
    """规则有效期管理页面"""
    cleanup_expired_rules()
    expiry = load_expiry()
    now = time.time()
    # 构建显示列表
    expiry_list = []
    for fp, ts in expiry.items():
        parts = fp.split("|")
        remaining = int(ts - now) if ts > now else 0
        expiry_list.append({
            "chain": parts[0], "protocol": parts[1],
            "src": parts[2], "dst": parts[3],
            "target": parts[4], "dport": parts[5] if len(parts) > 5 else "",
            "expire_at": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            "expired": ts <= now,
            "remaining": remaining,
        })
    rules = get_rules()
    return render_template("expiry.html", expiry_list=expiry_list, rules=rules)


@app.route("/expiry/set", methods=["POST"])
@login_required
def set_expiry():
    """为规则设置过期时间"""
    chain = request.form.get("chain", "INPUT")
    protocol = request.form.get("protocol", "all")
    src = request.form.get("src", "").strip()
    dst = request.form.get("dst", "").strip()
    target = request.form.get("target", "ACCEPT")
    dport = request.form.get("dport", "").strip()
    minutes = request.form.get("minutes", 60, type=int)

    minutes = max(1, min(minutes, 43200))  # 1分钟 ~ 30天

    fp = f"{chain}|{protocol}|{src}|{dst}|{target}|{dport}"
    expiry = load_expiry()
    expiry[fp] = time.time() + minutes * 60
    save_expiry(expiry)
    log_action("设置规则过期", f"{fp} -> {minutes}分钟后")
    flash(f"规则将在 {minutes} 分钟后自动过期", "success")
    return redirect(url_for("expiry_page"))


@app.route("/expiry/cancel", methods=["POST"])
@login_required
def cancel_expiry():
    """取消规则过期"""
    fp = request.form.get("fingerprint", "")
    expiry = load_expiry()
    if fp in expiry:
        del expiry[fp]
        save_expiry(expiry)
        log_action("取消规则过期", fp)
        flash("已取消过期设置", "success")
    return redirect(url_for("expiry_page"))


# ============ 流量异常告警 ============

def get_traffic_alert_config():
    """获取流量告警配置"""
    return load_json_config(TRAFFIC_ALERT_CONFIG, {
        "enabled": False,
        "rx_threshold_mbps": 100,  # 接收速率告警阈值 (Mbps)
        "tx_threshold_mbps": 100,  # 发送速率告警阈值
        "check_interval": 60,      # 检查间隔（秒）
    })


def check_traffic_anomaly():
    """检查流量异常，返回告警列表"""
    config = get_traffic_alert_config()
    if not config.get("enabled"):
        return []

    current = get_traffic_stats()
    alerts = []

    # 读取上次快照
    snapshot = load_json_config(TRAFFIC_SNAPSHOT_FILE, {})
    now = time.time()
    last_time = snapshot.get("time", 0)
    interval = now - last_time if last_time > 0 else config.get("check_interval", 60)

    if interval < 5:  # 间隔太短不检测
        return []

    for iface in current:
        name = iface["interface"]
        prev = snapshot.get("interfaces", {}).get(name, {})

        if prev:
            rx_diff = iface["rx_bytes"] - prev.get("rx_bytes", 0)
            tx_diff = iface["tx_bytes"] - prev.get("tx_bytes", 0)
            if rx_diff < 0:
                rx_diff = iface["rx_bytes"]  # 计数器重置
            if tx_diff < 0:
                tx_diff = iface["tx_bytes"]

            rx_mbps = (rx_diff * 8) / (interval * 1_000_000)
            tx_mbps = (tx_diff * 8) / (interval * 1_000_000)

            if rx_mbps > config.get("rx_threshold_mbps", 100):
                alerts.append(f"[{name}] 接收速率 {rx_mbps:.1f} Mbps 超过阈值 {config['rx_threshold_mbps']} Mbps")
            if tx_mbps > config.get("tx_threshold_mbps", 100):
                alerts.append(f"[{name}] 发送速率 {tx_mbps:.1f} Mbps 超过阈值 {config['tx_threshold_mbps']} Mbps")

    # 保存当前快照
    new_snapshot = {"time": now, "interfaces": {}}
    for iface in current:
        new_snapshot["interfaces"][iface["interface"]] = {
            "rx_bytes": iface["rx_bytes"],
            "tx_bytes": iface["tx_bytes"],
        }
    save_json_config(TRAFFIC_SNAPSHOT_FILE, new_snapshot)

    # 记录告警
    for alert in alerts:
        logger.warning(f"[流量告警] {alert}")

    return alerts


@app.route("/traffic-alert")
@login_required
def traffic_alert():
    """流量告警配置页面"""
    config = get_traffic_alert_config()
    alerts = check_traffic_anomaly()
    return render_template("traffic_alert.html", config=config, alerts=alerts)


@app.route("/traffic-alert/config", methods=["POST"])
@login_required
def traffic_alert_config():
    """更新流量告警配置"""
    config = {
        "enabled": request.form.get("enabled") == "on",
        "rx_threshold_mbps": request.form.get("rx_threshold", 100, type=int),
        "tx_threshold_mbps": request.form.get("tx_threshold", 100, type=int),
        "check_interval": request.form.get("interval", 60, type=int),
    }
    config["rx_threshold_mbps"] = max(1, min(config["rx_threshold_mbps"], 10000))
    config["tx_threshold_mbps"] = max(1, min(config["tx_threshold_mbps"], 10000))
    config["check_interval"] = max(10, min(config["check_interval"], 3600))
    save_json_config(TRAFFIC_ALERT_CONFIG, config)
    log_action("更新流量告警配置", str(config))
    flash("流量告警配置已更新", "success")
    return redirect(url_for("traffic_alert"))


# ============ 防火墙健康检查 ============

def health_check():
    """防火墙健康检查，返回检查项列表"""
    checks = []

    # 1. iptables 是否可用
    try:
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            checks.append({"name": "iptables 服务", "status": "ok", "detail": "iptables 正常运行"})
        else:
            checks.append({"name": "iptables 服务", "status": "error", "detail": f"iptables 错误: {result.stderr.strip()}"})
    except FileNotFoundError:
        checks.append({"name": "iptables 服务", "status": "error", "detail": "未找到 iptables 命令"})
    except Exception as e:
        checks.append({"name": "iptables 服务", "status": "error", "detail": str(e)})

    # 2. 默认策略检查
    try:
        result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            first_line = result.stdout.split("\n")[0] if result.stdout else ""
            if "DROP" in first_line or "REJECT" in first_line:
                policy = "DROP/REJECT"
                status = "ok"
            else:
                policy = "ACCEPT"
                status = "warning"
            checks.append({"name": "INPUT 默认策略", "status": status, "detail": f"当前策略: {policy}"})
    except Exception:
        checks.append({"name": "INPUT 默认策略", "status": "error", "detail": "无法获取"})

    # 3. 规则数量检查
    rules = get_rules()
    rule_count = len(rules)
    if rule_count > 500:
        checks.append({"name": "规则数量", "status": "warning", "detail": f"当前 {rule_count} 条规则，过多可能影响性能"})
    else:
        checks.append({"name": "规则数量", "status": "ok", "detail": f"当前 {rule_count} 条规则"})

    # 4. 冲突检查
    conflict_list = detect_conflicts()
    if conflict_list:
        checks.append({"name": "规则冲突", "status": "warning", "detail": f"发现 {len(conflict_list)} 个冲突/重复"})
    else:
        checks.append({"name": "规则冲突", "status": "ok", "detail": "无冲突"})

    # 5. 自定义链检查
    custom_chains = []
    try:
        table = iptc.Table(iptc.Table.FILTER)
        for chain in table.chains:
            if chain.name not in ("INPUT", "OUTPUT", "FORWARD"):
                custom_chains.append(chain.name)
    except Exception:
        pass
    if custom_chains:
        checks.append({"name": "自定义链", "status": "ok", "detail": f"存在自定义链: {', '.join(custom_chains)}"})
    else:
        checks.append({"name": "自定义链", "status": "ok", "detail": "无自定义链"})

    # 6. 日志文件检查
    try:
        if os.path.exists(LOG_FILE):
            size = os.path.getsize(LOG_FILE)
            if size > 50 * 1024 * 1024:  # 50MB
                checks.append({"name": "日志文件", "status": "warning", "detail": f"日志文件 {size // 1024 // 1024}MB，建议清理"})
            else:
                checks.append({"name": "日志文件", "status": "ok", "detail": f"日志文件 {size // 1024}KB"})
        else:
            checks.append({"name": "日志文件", "status": "warning", "detail": "日志文件不存在"})
    except Exception:
        checks.append({"name": "日志文件", "status": "error", "detail": "无法读取日志文件"})

    # 7. ipset 检查
    try:
        result = subprocess.run(["ipset", "list"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            sets = [l for l in result.stdout.split("\n") if l.startswith("Name: ")]
            checks.append({"name": "ipset 集合", "status": "ok", "detail": f"共 {len(sets)} 个集合"})
        else:
            checks.append({"name": "ipset 集合", "status": "ok", "detail": "ipset 未使用或不可用"})
    except FileNotFoundError:
        checks.append({"name": "ipset 集合", "status": "ok", "detail": "未安装 ipset"})

    # 8. 过期规则检查
    expiry = load_expiry()
    now = time.time()
    expired_count = sum(1 for v in expiry.values() if v <= now)
    if expired_count > 0:
        checks.append({"name": "过期规则", "status": "warning", "detail": f"有 {expired_count} 条规则已过期待清理"})
    else:
        checks.append({"name": "过期规则", "status": "ok", "detail": f"共 {len(expiry)} 条规则设置了过期时间"})

    # 9. 系统资源
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    avail_kb = int(line.split()[1])
                    if avail_kb < 100 * 1024:  # < 100MB
                        checks.append({"name": "可用内存", "status": "warning", "detail": f"{avail_kb // 1024}MB"})
                    else:
                        checks.append({"name": "可用内存", "status": "ok", "detail": f"{avail_kb // 1024}MB"})
                    break
    except Exception:
        pass

    return checks


@app.route("/health")
@login_required
def health():
    """防火墙健康检查页面"""
    checks = health_check()
    return render_template("health.html", checks=checks)


# ============ 错误处理器 ============

@app.errorhandler(404)
def not_found(e):
    """404 错误处理"""
    if request.path.startswith("/api/"):
        return jsonify({"error": "资源不存在"}), 404
    flash("页面不存在", "warning")
    return redirect(url_for("index"))


@app.errorhandler(405)
def method_not_allowed(e):
    """405 错误处理"""
    if request.path.startswith("/api/"):
        return jsonify({"error": "请求方法不允许"}), 405
    flash("请求方法不允许", "warning")
    return redirect(url_for("index"))


@app.errorhandler(413)
def too_large(e):
    """413 文件过大"""
    flash("上传文件过大，最大 2MB", "danger")
    return redirect(url_for("index"))


@app.errorhandler(500)
def internal_error(e):
    """500 错误处理"""
    logger.error(f"服务器内部错误: {e}")
    if request.path.startswith("/api/"):
        return jsonify({"error": "服务器内部错误"}), 500
    flash("服务器内部错误，请查看日志", "danger")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # host 网络模式下绑定 0.0.0.0，通过反向代理限制访问
    host = os.environ.get("LISTEN_HOST", "127.0.0.1")
    port = int(os.environ.get("LISTEN_PORT", 8901))
    app.run(host=host, port=port, debug=False)
