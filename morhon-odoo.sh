#!/bin/bash

# 茂亨Odoo外贸专用版管理脚本 - 优化版
# 单实例版本，支持本地模式和域名模式
# 版本: 6.2
# GitHub: https://github.com/morhon-tech/morhon-odoo
# 
# 功能特性:
# - 自动检测现有实例（脚本管理/手动部署）
# - 支持本地模式和域名模式部署
# - 自动SSL证书获取和配置
# - 完整的备份和恢复功能
# - 手动实例迁移到脚本管理
# - 性能优化配置
# - 安全加固设置

set -e

# 配置变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTANCE_DIR="/opt/morhon-odoo"
BACKUP_DIR="/var/backups/morhon-odoo"
LOG_DIR="/var/log/morhon-odoo"

# 固定卷名
DB_VOLUME_NAME="odoo-db-data"
ODOO_VOLUME_NAME="odoo-web-data"

# 固定镜像配置
ODOO_IMAGE="registry.cn-hangzhou.aliyuncs.com/morhon_hub/mh_odoosaas_v17:latest"
POSTGRES_IMAGE="registry.cn-hangzhou.aliyuncs.com/morhon_hub/postgres:latest"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 全局状态变量
DETECTED_INSTANCE_TYPE=""  # none, script, manual
DETECTED_ODOO_CONTAINER=""
DETECTED_DB_CONTAINER=""
DETECTED_DOMAIN=""
DETECTED_DB_PASSWORD=""

# 日志函数
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_DIR/morhon-odoo.log"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_DIR/morhon-odoo.log" >&2
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a "$LOG_DIR/morhon-odoo.log"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_DIR/morhon-odoo.log"
}

# 检查是否为sudo用户
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "此脚本需要root权限，请使用sudo运行"
        exit 1
    fi
}

# 一次性检测所有信息
detect_environment() {
    log_info "检测系统环境..."
    
    # 创建必要目录
    mkdir -p "$INSTANCE_DIR" "$BACKUP_DIR" "$LOG_DIR"
    
    # 1. 检测脚本管理的实例
    if [ -f "$INSTANCE_DIR/docker-compose.yml" ]; then
        DETECTED_INSTANCE_TYPE="script"
        log "检测到脚本管理的实例: $INSTANCE_DIR"
        return 0
    fi
    
    # 2. 检测手动部署的实例
    local odoo_container=$(find_container_by_image "$ODOO_IMAGE" "morhon" "odoo")
    
    if [ -n "$odoo_container" ]; then
        DETECTED_INSTANCE_TYPE="manual"
        DETECTED_ODOO_CONTAINER="$odoo_container"
        
        # 获取数据库容器
        DETECTED_DB_CONTAINER=$(find_container_by_image "postgres" "postgres" "db")
        
        # 尝试从容器获取域名和密码
        extract_instance_info
        log "检测到手动部署的实例: $DETECTED_ODOO_CONTAINER"
        return 0
    fi
    
    # 3. 无实例
    DETECTED_INSTANCE_TYPE="none"
    log "未检测到现有实例"
    
    return 0
}

# 通过镜像或名称查找容器
find_container_by_image() {
    local primary_image="$1"
    shift
    
    # 首先通过镜像查找
    local container=$(docker ps -a --filter "ancestor=$primary_image" --format "{{.Names}}" 2>/dev/null | head -1)
    
    # 如果未找到，通过名称查找
    if [ -z "$container" ]; then
        for name_filter in "$@"; do
            container=$(docker ps -a --filter "name=$name_filter" --format "{{.Names}}" 2>/dev/null | head -1)
            [ -n "$container" ] && break
        done
    fi
    
    echo "$container"
}

# 从手动部署实例提取信息
extract_instance_info() {
    log_info "从手动部署实例提取信息..."
    
    # 1. 尝试从odoo容器获取odoo.conf内容
    if [ -n "$DETECTED_ODOO_CONTAINER" ]; then
        extract_odoo_config_info
    fi
    
    # 2. 尝试从数据库容器获取密码
    if [ -n "$DETECTED_DB_CONTAINER" ]; then
        extract_db_password
    fi
    
    # 3. 尝试从Nginx配置获取域名
    if [ -z "$DETECTED_DOMAIN" ]; then
        extract_nginx_domain
    fi
    
    return 0
}

# 提取Odoo配置信息
extract_odoo_config_info() {
    local odoo_conf_content=$(docker exec "$DETECTED_ODOO_CONTAINER" cat /etc/odoo/odoo.conf 2>/dev/null || docker exec "$DETECTED_ODOO_CONTAINER" cat /odoo/config/odoo.conf 2>/dev/null || true)
    
    if [ -n "$odoo_conf_content" ]; then
        # 提取数据库名（可能是域名）
        local db_name=$(echo "$odoo_conf_content" | grep "^db_name" | cut -d'=' -f2 | sed 's/[[:space:]]*//g')
        if [[ "$db_name" == *.* ]]; then
            DETECTED_DOMAIN=$(echo "$db_name" | awk -F'.' '{print $(NF-1)"."$NF}')
            log "从数据库名提取到域名: $DETECTED_DOMAIN"
        fi
    fi
    
    # 尝试从容器环境变量获取域名
    if [ -z "$DETECTED_DOMAIN" ]; then
        local env_vars=$(docker inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$DETECTED_ODOO_CONTAINER" 2>/dev/null || true)
        DETECTED_DOMAIN=$(echo "$env_vars" | grep -E "DOMAIN|HOSTNAME" | cut -d'=' -f2 | head -1)
    fi
}

# 提取数据库密码
extract_db_password() {
    DETECTED_DB_PASSWORD=$(docker exec "$DETECTED_DB_CONTAINER" env 2>/dev/null | grep "POSTGRES_PASSWORD" | cut -d'=' -f2 || echo "odoo")
    log "提取到数据库密码"
}

# 提取Nginx域名配置
extract_nginx_domain() {
    if [ -d "/etc/nginx/sites-enabled" ]; then
        local nginx_domain=$(grep -r "server_name" /etc/nginx/sites-enabled/ 2>/dev/null | grep -v "_" | head -1 | awk '{print $2}' | sed 's/;//')
        if [[ "$nginx_domain" == *.* ]] && [ "$nginx_domain" != "localhost" ]; then
            DETECTED_DOMAIN="$nginx_domain"
            log "从Nginx配置提取到域名: $DETECTED_DOMAIN"
        fi
    fi
}

# 获取服务器IP地址
get_server_ip() {
    local ip=""
    
    # 方法1: 使用ip命令
    ip=$(ip route get 1 2>/dev/null | awk '{print $7; exit}' || true)
    
    # 方法2: 使用hostname
    if [ -z "$ip" ] || [[ "$ip" == *" "* ]] || [[ "$ip" == "127.0.0.1" ]]; then
        ip=$(hostname -I | awk '{print $1}')
    fi
    
    if [ -z "$ip" ] || [[ "$ip" == *" "* ]]; then
        ip="127.0.0.1"
    fi
    
    echo "$ip"
}

# 初始化环境
init_environment() {
    log "初始化环境..."
    
    # 更新系统
    log "更新系统包..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get upgrade -y
    
    # 安装系统依赖
    log "安装系统依赖..."
    apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        tar \
        gzip \
        python3 \
        python3-pip \
        postgresql-client \
        certbot \
        python3-certbot-nginx \
        nginx \
        ufw \
        net-tools \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release
    
    # 安装Docker
    if ! command -v docker &> /dev/null; then
        install_docker
    fi
    
    # 安装Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        install_docker_compose
    fi
    
    # 配置防火墙
    configure_firewall
    
    # 配置Nginx
    configure_nginx
    
    log "环境初始化完成"
    return 0
}

# 安装Docker
install_docker() {
    log "安装Docker..."
    
    # 检查系统类型
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "无法检测操作系统类型"
        return 1
    fi
    
    case $OS in
        ubuntu|debian)
            # 添加Docker官方GPG密钥
            mkdir -p /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            
            apt-get update
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        centos|rhel|fedora)
            # CentOS/RHEL/Fedora
            yum install -y yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            systemctl start docker
            systemctl enable docker
            ;;
        *)
            log_error "不支持的操作系统: $OS"
            return 1
            ;;
    esac
    
    # 启动Docker服务
    systemctl start docker
    systemctl enable docker
    
    # 添加当前用户到docker组（如果不是root）
    if [ "$EUID" -ne 0 ] && [ -n "$SUDO_USER" ]; then
        usermod -aG docker "$SUDO_USER"
        log "已将用户 $SUDO_USER 添加到docker组，请重新登录以生效"
    fi
    
    log "Docker安装完成"
}

# 安装Docker Compose
install_docker_compose() {
    log "安装Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    log "Docker Compose安装完成"
}

# 配置防火墙
configure_firewall() {
    log "配置防火墙..."
    
    # 重置防火墙规则
    ufw --force reset
    
    # 默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许SSH
    ufw allow 22/tcp
    log "已允许SSH端口 (22/tcp)"
    
    # 允许HTTP
    ufw allow 80/tcp
    log "已允许HTTP端口 (80/tcp)"
    
    # 允许HTTPS
    ufw allow 443/tcp
    log "已允许HTTPS端口 (443/tcp)"
    
    # 启用UFW
    ufw --force enable
    
    log "防火墙配置完成"
}

# 配置Nginx
configure_nginx() {
    log "配置Nginx..."
    
    # 备份原始配置
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # 创建优化的nginx配置
    tee /etc/nginx/nginx.conf > /dev/null << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    # 基本设置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME类型
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # 日志格式
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;
    
    # 限制请求大小
    client_max_body_size 100M;
    client_body_timeout 120s;
    
    # Gzip压缩
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_min_length 1000;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;
    
    # SSL设置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # 包含其他配置
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # 创建站点目录
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    
    # 测试配置
    nginx -t
    
    # 重启Nginx
    systemctl restart nginx
    
    log "Nginx配置完成"
}

# 创建Docker卷
create_docker_volumes() {
    log "创建Docker卷..."
    
    create_volume "$DB_VOLUME_NAME" "数据库卷"
    create_volume "$ODOO_VOLUME_NAME" "Odoo文件卷"
    
    log "Docker卷创建完成"
}

# 创建Docker卷（辅助函数）
create_volume() {
    local volume_name="$1"
    local description="$2"
    
    if ! docker volume ls | grep -q "$volume_name"; then
        docker volume create "$volume_name"
        log "创建$description: $volume_name"
    else
        log "$description已存在: $volume_name"
    fi
}

# 拉取Docker镜像（专有镜像，无备用源）
get_docker_image() {
    local image_name="$1"
    
    log "拉取Docker镜像: $image_name"
    
    if docker pull "$image_name"; then
        log "镜像拉取成功: $image_name"
        return 0
    else
        log_error "镜像拉取失败: $image_name"
        log_error "请检查网络连接和镜像仓库权限"
        return 1
    fi
}

# 生成docker-compose文件
generate_docker_compose() {
    local deployment_type="$1"  # domain 或 local
    local domain="$2"
    local use_www="${3:-no}"
    
    # 获取系统信息用于优化
    local cpu_cores=$(nproc)
    local total_mem=$(free -g | awk '/^Mem:/{print $2}')
    
    # 计算workers数量
    local workers=$(calculate_workers "$cpu_cores" "$total_mem")
    
    # 创建目录结构
    mkdir -p "$INSTANCE_DIR/config"
    mkdir -p "$INSTANCE_DIR/backups"
    mkdir -p "$INSTANCE_DIR/logs"
    
    # 创建odoo配置文件
    create_odoo_config "$workers" "$total_mem"
    
    # 创建docker-compose.yml
    create_docker_compose_config
    
    # 创建环境变量文件
    create_env_file "$deployment_type" "$domain" "$use_www"
    
    # 根据部署类型创建Nginx配置
    if [ "$deployment_type" = "domain" ]; then
        create_nginx_domain_config "$domain" "$use_www"
    else
        create_nginx_local_config
    fi
    
    log "配置文件生成完成"
}

# 计算workers数量
calculate_workers() {
    local cpu_cores="$1"
    local total_mem="$2"
    local workers=4
    
    [ "$cpu_cores" -ge 8 ] && workers=8
    [ "$cpu_cores" -ge 4 ] && workers=6
    [ "$cpu_cores" -ge 2 ] && workers=4
    [ "$cpu_cores" -eq 1 ] && workers=2
    
    echo "$workers"
}

# 创建odoo配置文件
create_odoo_config() {
    local workers="$1"
    local total_mem="$2"
    
    # 计算内存限制（更保守的设置）
    local memory_hard=$((total_mem * 200))
    local memory_soft=$((total_mem * 150))
    
    # 确保最小值
    [ "$memory_hard" -lt 512 ] && memory_hard=512
    [ "$memory_soft" -lt 384 ] && memory_soft=384
    
    cat > "$INSTANCE_DIR/config/odoo.conf" << EOF
[options]
# 基本配置
admin_passwd = \${ADMIN_PASSWORD}
addons_path = /mnt/extra-addons,/mnt/odoo/addons
data_dir = /var/lib/odoo
without_demo = all
proxy_mode = True

# 性能配置
workers = $workers
limit_memory_hard = ${memory_hard}M
limit_memory_soft = ${memory_soft}M
max_cron_threads = $((workers > 4 ? 2 : 1))
limit_time_cpu = 600
limit_time_real = 1200
limit_request = 8192

# 数据库配置
db_host = db
db_port = 5432
db_user = odoo
db_password = \${DB_PASSWORD}
db_name = postgres
list_db = False
db_sslmode = prefer

# 日志配置
log_level = info
log_handler = :INFO
logfile = /var/log/odoo/odoo.log

# 安全配置
server_wide_modules = base,web
unaccent = True

# 邮件配置
email_from = noreply@localhost
smtp_server = localhost
smtp_port = 25
smtp_ssl = False
smtp_user = False
smtp_password = False
EOF
}

# 创建docker-compose配置文件
create_docker_compose_config() {
    cat > "$INSTANCE_DIR/docker-compose.yml" << EOF
version: '3.8'

services:
  db:
    image: $POSTGRES_IMAGE
    container_name: morhon-odoo-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: postgres
      POSTGRES_USER: odoo
      POSTGRES_PASSWORD: \${DB_PASSWORD}
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - $DB_VOLUME_NAME:/var/lib/postgresql/data/pgdata
      - $INSTANCE_DIR/backups:/backups
    networks:
      - morhon-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U odoo -d postgres"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  odoo:
    image: $ODOO_IMAGE
    container_name: morhon-odoo
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      HOST: db
      PORT: 5432
      USER: odoo
      PASSWORD: \${DB_PASSWORD}
      DB_NAME: postgres
      ADMIN_PASSWORD: \${ADMIN_PASSWORD}
    volumes:
      - $INSTANCE_DIR/config/odoo.conf:/etc/odoo/odoo.conf:ro
      - $ODOO_VOLUME_NAME:/var/lib/odoo
      - $INSTANCE_DIR/logs:/var/log/odoo
      - $INSTANCE_DIR/backups:/backups
    ports:
      - "127.0.0.1:8069:8069"
      - "127.0.0.1:8072:8072"
    networks:
      - morhon-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8069/web/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 120s

networks:
  morhon-network:
    driver: bridge
    name: morhon-network

volumes:
  $DB_VOLUME_NAME:
    external: true
  $ODOO_VOLUME_NAME:
    external: true
EOF
}

# 创建环境变量文件
create_env_file() {
    local deployment_type="$1"
    local domain="$2"
    local use_www="$3"
    local db_password="${DETECTED_DB_PASSWORD:-$(openssl rand -base64 32)}"
    local admin_password="$(openssl rand -base64 24)"
    
    cat > "$INSTANCE_DIR/.env" << EOF
# 茂亨Odoo环境变量配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

# 数据库配置
DB_PASSWORD=$db_password

# 管理员配置
ADMIN_PASSWORD=$admin_password

# 部署配置
DEPLOYMENT_TYPE=$deployment_type
DOMAIN=$domain
USE_WWW=$use_www

# 版本信息
SCRIPT_VERSION=6.2
ODOO_IMAGE=$ODOO_IMAGE
POSTGRES_IMAGE=$POSTGRES_IMAGE
EOF

    # 设置文件权限
    chmod 600 "$INSTANCE_DIR/.env"
    
    log "环境变量文件已创建: $INSTANCE_DIR/.env"
    log "管理员密码: $admin_password"
}

# 创建Nginx域名配置
create_nginx_domain_config() {
    local domain="$1"
    local use_www="$2"
    
    local config_file="/etc/nginx/sites-available/morhon-odoo"
    
    # 根据是否使用www生成server_name
    local server_name
    if [ "$use_www" = "yes" ]; then
        server_name="$domain www.$domain"
    else
        server_name="$domain"
    fi
    
    tee "$config_file" > /dev/null << EOF
# 茂亨Odoo域名模式 - $domain

# HTTP重定向到HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $server_name;
    
    # Certbot验证
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    # 重定向到HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS服务器
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $server_name;
    
    # SSL证书（Certbot会自动配置）
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    # 安全头部
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # 代理设置
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
    
    # 禁止访问数据库管理界面
    location ~* /(web|api)/database/ {
        deny all;
        return 403;
    }
    
    # 长轮询请求
    location /longpolling {
        proxy_pass http://127.0.0.1:8072;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # 静态文件
    location ~* /web/static/ {
        proxy_buffering on;
        expires 864000;
        proxy_pass http://127.0.0.1:8069;
    }
    
    # 主请求
    location / {
        proxy_pass http://127.0.0.1:8069;
        proxy_redirect off;
    }
    
    access_log /var/log/nginx/morhon-odoo-access.log;
    error_log /var/log/nginx/morhon-odoo-error.log;
}
EOF
    
    # 启用站点
    ln -sf "$config_file" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default
    
    log "Nginx域名配置创建完成"
}

# 创建Nginx本地配置
create_nginx_local_config() {
    local config_file="/etc/nginx/sites-available/morhon-odoo"
    local server_ip=$(get_server_ip)
    
    tee "$config_file" > /dev/null << EOF
# 茂亨Odoo本地模式 - 通过IP访问

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    # 安全头部
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # 代理设置
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
    
    # 禁止访问数据库管理界面
    location ~* /(web|api)/database/ {
        deny all;
        return 403;
    }
    
    # 长轮询请求
    location /longpolling {
        proxy_pass http://127.0.0.1:8072;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # 静态文件
    location ~* /web/static/ {
        proxy_buffering on;
        expires 864000;
        proxy_pass http://127.0.0.1:8069;
    }
    
    # 主请求
    location / {
        proxy_pass http://127.0.0.1:8069;
        proxy_redirect off;
    }
    
    access_log /var/log/nginx/morhon-odoo-access.log;
    error_log /var/log/nginx/morhon-odoo-error.log;
}
EOF
    
    # 启用站点
    ln -sf "$config_file" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default
    
    log "Nginx本地配置创建完成"
    log "将通过IP地址访问: http://$server_ip"
}

# 获取SSL证书
get_ssl_certificate() {
    local domain="$1"
    local use_www="$2"
    
    log "获取SSL证书..."
    
    # 创建Certbot目录
    mkdir -p /var/www/certbot
    
    # 根据是否使用www生成域名列表
    local domain_args=""
    if [ "$use_www" = "yes" ]; then
        domain_args="-d $domain -d www.$domain"
    else
        domain_args="-d $domain"
    fi
    
    # 检查是否已有证书
    if [ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]; then
        log "SSL证书已存在，尝试续期..."
        if certbot renew --dry-run; then
            log "SSL证书有效"
            return 0
        fi
    fi
    
    # 获取新证书
    if certbot certonly --webroot \
        -w /var/www/certbot \
        $domain_args \
        --non-interactive \
        --agree-tos \
        --email "admin@$domain" \
        --force-renewal; then
        log "SSL证书获取成功"
        
        # 设置自动续期
        setup_ssl_renewal "$domain"
        return 0
    else
        log_warn "无法获取SSL证书，将使用HTTP模式"
        create_nginx_http_config "$domain" "$use_www"
        return 1
    fi
}

# 设置SSL证书自动续期
setup_ssl_renewal() {
    local domain="$1"
    
    # 创建续期脚本
    cat > /etc/cron.d/certbot-renewal << EOF
# 每天凌晨2点检查证书续期
0 2 * * * root certbot renew --quiet --post-hook "systemctl reload nginx"
EOF
    
    log "SSL证书自动续期已设置"
}

# 创建HTTP模式的Nginx配置（SSL获取失败时的备用方案）
create_nginx_http_config() {
    local domain="$1"
    local use_www="$2"
    
    local config_file="/etc/nginx/sites-available/morhon-odoo"
    
    # 根据是否使用www生成server_name
    local server_name
    if [ "$use_www" = "yes" ]; then
        server_name="$domain www.$domain"
    else
        server_name="$domain"
    fi
    
    tee "$config_file" > /dev/null << EOF
# 茂亨Odoo HTTP模式 - $domain (SSL获取失败备用方案)

server {
    listen 80;
    listen [::]:80;
    server_name $server_name;
    
    # Certbot验证目录
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    # 安全头部
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # 代理设置
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;
    
    # 禁止访问数据库管理界面
    location ~* /(web|api)/database/ {
        deny all;
        return 403;
    }
    
    # 长轮询请求
    location /longpolling {
        proxy_pass http://127.0.0.1:8072;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # 静态文件
    location ~* /web/static/ {
        proxy_buffering on;
        expires 864000;
        proxy_pass http://127.0.0.1:8069;
    }
    
    # 主请求
    location / {
        proxy_pass http://127.0.0.1:8069;
        proxy_redirect off;
    }
    
    access_log /var/log/nginx/morhon-odoo-access.log;
    error_log /var/log/nginx/morhon-odoo-error.log;
}
EOF
    
    # 启用站点
    ln -sf "$config_file" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default
    
    log "Nginx HTTP配置创建完成（SSL备用方案）"
}

# 迁移手动部署实例到脚本管理
migrate_manual_instance() {
    log "开始迁移手动部署实例..."
    
    # 确认迁移
    if ! confirm_action "迁移操作将执行以下步骤:\n  1. 备份现有数据\n  2. 停止并删除旧容器\n  3. 创建脚本管理实例\n  4. 恢复数据到新实例"; then
        log "取消迁移"
        return 1
    fi
    
    # 备份现有数据
    local backup_timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_path="$BACKUP_DIR/migration_$backup_timestamp"
    mkdir -p "$backup_path"
    
    log "备份现有数据..."
    backup_existing_data "$backup_path"
    
    # 询问部署模式
    local deployment_type domain use_www
    get_deployment_info "$deployment_type" "$domain" "$use_www"
    
    # 停止并删除旧容器
    log "清理旧容器..."
    cleanup_old_containers
    
    # 创建新的脚本管理实例
    log "创建新实例..."
    create_new_instance "$deployment_type" "$domain" "$use_www"
    
    # 恢复数据库（如果有备份）
    restore_database_backup "$backup_path"
    
    # 重启Nginx
    systemctl reload nginx
    
    log "迁移完成！"
    show_deployment_info "$deployment_type" "$domain" "$backup_path"
    
    return 0
}

# 确认操作
confirm_action() {
    local message="$1"
    echo ""
    echo -e "${YELLOW}$message${NC}"
    echo ""
    read -p "是否继续？(y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]]
}

# 备份现有数据
backup_existing_data() {
    local backup_path="$1"
    
    # 备份数据库
    if [ -n "$DETECTED_DB_CONTAINER" ]; then
        docker exec "$DETECTED_DB_CONTAINER" pg_dumpall -U postgres | gzip > "$backup_path/database.sql.gz" 2>/dev/null || \
        docker exec "$DETECTED_DB_CONTAINER" pg_dumpall -U odoo | gzip > "$backup_path/database.sql.gz" 2>/dev/null || \
        log_warn "数据库备份失败"
    fi
}

# 获取部署信息
get_deployment_info() {
    local -n deployment_type_ref=$1
    local -n domain_ref=$2
    local -n use_www_ref=$3
    
    deployment_type_ref="local"
    domain_ref=""
    use_www_ref="no"
    
    if [ -n "$DETECTED_DOMAIN" ]; then
        echo "检测到现有域名: $DETECTED_DOMAIN"
        read -p "是否使用此域名？(Y/n): " use_domain
        if [[ ! "$use_domain" =~ ^[Nn]$ ]]; then
            deployment_type_ref="domain"
            domain_ref="$DETECTED_DOMAIN"
            
            # 自动检测是否带www
            if [[ "$domain_ref" == www.* ]]; then
                use_www_ref="yes"
            fi
            # 原手动选择已替换为自动检测
        fi
    fi
    
    # 如果没有域名，询问是否使用域名模式
    if [ -z "$domain_ref" ]; then
        read -p "是否使用域名模式？(y/N): " use_domain
        if [[ "$use_domain" =~ ^[Yy]$ ]]; then
            deployment_type_ref="domain"
            read -p "请输入域名: " domain_ref
            [ -z "$domain_ref" ] && deployment_type_ref="local"
        fi
    fi
}

# 清理旧容器
cleanup_old_containers() {
    [ -n "$DETECTED_ODOO_CONTAINER" ] && docker stop "$DETECTED_ODOO_CONTAINER" 2>/dev/null || true
    [ -n "$DETECTED_DB_CONTAINER" ] && docker stop "$DETECTED_DB_CONTAINER" 2>/dev/null || true
    [ -n "$DETECTED_ODOO_CONTAINER" ] && docker rm "$DETECTED_ODOO_CONTAINER" 2>/dev/null || true
    [ -n "$DETECTED_DB_CONTAINER" ] && docker rm "$DETECTED_DB_CONTAINER" 2>/dev/null || true
}

# 创建新实例
create_new_instance() {
    local deployment_type="$1"
    local domain="$2"
    local use_www="$3"
    
    log "创建新实例..."
    
    # 创建Docker卷
    create_docker_volumes
    
    # 生成配置文件
    generate_docker_compose "$deployment_type" "$domain" "$use_www"
    
    # 拉取Docker镜像
    get_docker_image "$POSTGRES_IMAGE"
    get_docker_image "$ODOO_IMAGE"
    
    # 启动服务并等待就绪
    start_services
    
    # 如果是域名模式，配置SSL和Nginx
    if [ "$deployment_type" = "domain" ]; then
        get_ssl_certificate "$domain" "$use_www"
    fi
    
    log "新实例创建完成"
}
    
# 启动服务并等待就绪
start_services() {
    log "启动服务..."
    cd "$INSTANCE_DIR"
    
    # 启动服务
    docker-compose up -d
    
    # 等待数据库就绪
    log "等待数据库启动..."
    local db_ready=false
    for i in {1..30}; do
        if docker-compose exec -T db pg_isready -U odoo -d postgres >/dev/null 2>&1; then
            db_ready=true
            break
        fi
        sleep 2
        echo -n "."
    done
    echo ""
    
    if [ "$db_ready" = false ]; then
        log_error "数据库启动超时"
        return 1
    fi
    
    log "数据库已就绪"
    
    # 等待Odoo就绪
    log "等待Odoo启动..."
    local odoo_ready=false
    for i in {1..60}; do
        if curl -s http://127.0.0.1:8069/web/health >/dev/null 2>&1; then
            odoo_ready=true
            break
        fi
        sleep 3
        echo -n "."
    done
    echo ""
    
    if [ "$odoo_ready" = false ]; then
        log_warn "Odoo启动检查超时，但服务可能仍在启动中"
    else
        log "Odoo已就绪"
    fi
    
    return 0
}

# 恢复数据库备份
restore_database_backup() {
    local backup_path="$1"
    
    if [ -f "$backup_path/database.sql.gz" ]; then
        log "恢复数据库..."
        gunzip -c "$backup_path/database.sql.gz" | docker exec -i morhon-odoo-db psql -U odoo postgres 2>/dev/null || \
        log_warn "数据库恢复失败，新实例将使用空数据库"
    fi
}

# 显示部署信息
show_deployment_info() {
    local deployment_type="$1"
    local domain="$2"
    local backup_path="$3"
    
    log "实例目录: $INSTANCE_DIR"
    log "备份文件: $backup_path"
    
    if [ "$deployment_type" = "domain" ]; then
        log "访问地址: https://$domain"
    else
        local server_ip=$(get_server_ip)
        log "访问地址: http://$server_ip"
    fi
}

# 从本地备份恢复
restore_from_backup() {
    log "从本地备份恢复..."
    
    # 查找备份文件（优先查找脚本同目录，然后查找脚本目录）
    local backup_files=()
    
    # 首先在脚本同目录查找备份文件
    local script_backup_files=($(find "$SCRIPT_DIR" -maxdepth 1 -name "*.tar.gz" -type f 2>/dev/null))
    
    # 然后在默认备份目录查找
    local default_backup_files=()
    if [ -d "$BACKUP_DIR" ]; then
        default_backup_files=($(find "$BACKUP_DIR" -maxdepth 1 -name "*.tar.gz" -type f 2>/dev/null))
    fi
    
    # 合并备份文件列表，脚本目录的文件优先
    backup_files=("${script_backup_files[@]}" "${default_backup_files[@]}")
    
    if [ ${#backup_files[@]} -eq 0 ]; then
        log_error "未找到备份文件"
        log "请将备份文件(.tar.gz)放在脚本同目录下，或放在 $BACKUP_DIR 目录中"
        return 1
    fi
    
    # 选择备份文件
    local backup_file=$(select_backup_file "${backup_files[@]}")
    [ -z "$backup_file" ] && return 1
    
    # 询问域名
    local deployment_type domain use_www
    get_restore_deployment_info "$deployment_type" "$domain" "$use_www"
    
    # 解压备份
    local temp_dir="/tmp/restore_$(date '+%Y%m%d%H%M%S')"
    mkdir -p "$temp_dir"
    
    log "解压备份文件: $(basename "$backup_file")"
    if ! tar -xzf "$backup_file" -C "$temp_dir"; then
        log_error "备份文件解压失败"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 查找备份数据
    local backup_data=$(find "$temp_dir" -name "database.sql.gz" -type f | head -1)
    if [ -z "$backup_data" ]; then
        log_error "备份文件中未找到数据库文件"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 检查备份完整性
    local backup_info=$(find "$temp_dir" -name "backup_info.txt" -type f | head -1)
    if [ -n "$backup_info" ]; then
        log "备份信息:"
        cat "$backup_info"
        echo ""
        
        read -p "确认恢复此备份？(y/N): " confirm_restore
        if [[ ! "$confirm_restore" =~ ^[Yy]$ ]]; then
            log "取消恢复"
            rm -rf "$temp_dir"
            return 1
        fi
    fi
    
    # 创建新实例
    log "创建新实例..."
    create_new_instance "$deployment_type" "$domain" "$use_www"
    
    # 等待服务完全启动
    sleep 5
    
    # 恢复数据库
    restore_from_backup_file "$backup_data"
    
    # 恢复其他配置（如果存在）
    restore_additional_configs "$temp_dir"
    
    # 重启Nginx
    systemctl reload nginx
    
    # 清理临时文件
    rm -rf "$temp_dir"
    
    log "恢复完成！"
    
    if [ "$deployment_type" = "domain" ]; then
        log "访问地址: https://$domain"
    else
        local server_ip=$(get_server_ip)
        log "访问地址: http://$server_ip"
    fi
    
    # 显示恢复后的信息
    show_restore_summary "$backup_file"
    
    return 0
}

# 恢复其他配置文件
restore_additional_configs() {
    local temp_dir="$1"
    
    # 恢复环境变量（如果备份中有且当前没有冲突）
    local backup_env=$(find "$temp_dir" -name ".env" -type f | head -1)
    if [ -n "$backup_env" ] && [ -f "$backup_env" ]; then
        log "发现备份的环境变量配置"
        
        # 提取备份中的管理员密码
        local backup_admin_pass=$(grep "^ADMIN_PASSWORD=" "$backup_env" | cut -d'=' -f2)
        if [ -n "$backup_admin_pass" ]; then
            log "恢复管理员密码..."
            sed -i "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$backup_admin_pass/" "$INSTANCE_DIR/.env"
        fi
    fi
    
    # 恢复Nginx配置（如果备份中有）
    local backup_nginx=$(find "$temp_dir" -name "nginx-config" -type f | head -1)
    if [ -n "$backup_nginx" ] && [ -f "$backup_nginx" ]; then
        log "发现备份的Nginx配置，可手动参考恢复"
    fi
}

# 显示恢复摘要
show_restore_summary() {
    local backup_file="$1"
    
    echo ""
    echo -e "${GREEN}恢复摘要${NC}"
    echo "===================="
    echo "备份文件: $(basename "$backup_file")"
    echo "实例目录: $INSTANCE_DIR"
    echo "恢复时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "后续操作建议:"
    echo "1. 检查系统状态: 在脚本菜单中选择'系统状态检查'"
    echo "2. 修改密码: 建议修改管理员密码"
    echo "3. 检查配置: 确认Odoo配置是否符合当前环境"
    echo "4. 创建备份: 恢复完成后建议立即创建新备份"
    echo ""
}

# 选择备份文件
select_backup_file() {
    local backup_files=("$@")
    
    echo ""
    echo "发现备份文件:"
    echo "===================="
    
    for i in "${!backup_files[@]}"; do
        local file="${backup_files[$i]}"
        local size=$(du -h "$file" 2>/dev/null | cut -f1)
        local date=$(stat -c %y "$file" 2>/dev/null | cut -d' ' -f1)
        
        # 检查是否在脚本目录
        local location="默认备份目录"
        if [[ "$file" == "$SCRIPT_DIR"* ]]; then
            location="脚本目录"
        fi
        
        echo "$((i+1))) $(basename "$file")"
        echo "    大小: $size | 日期: $date | 位置: $location"
        echo ""
    done
    
    read -p "选择要恢复的备份文件 (1-${#backup_files[@]}) [默认: 1]: " choice
    choice=${choice:-1}
    
    if [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backup_files[@]} ]; then
        log_error "无效选择"
        return
    fi
    
    local backup_file="${backup_files[$((choice-1))]}"
    log "选择恢复: $(basename "$backup_file")"
    echo "$backup_file"
}

# 获取恢复部署信息
get_restore_deployment_info() {
    local -n deployment_type_ref=$1
    local -n domain_ref=$2
    local -n use_www_ref=$3
    
    echo ""
    echo "请输入域名（直接回车将使用本地模式）:"
    read -p "域名: " domain_ref
    
    deployment_type_ref="local"
    use_www_ref="no"
    
    if [ -n "$domain_ref" ]; then
        deployment_type_ref="domain"
        # 自动检测是否带www
            if [[ "$domain_ref" == www.* ]]; then
                use_www_ref="yes"
            fi
            # 原手动选择已替换为自动检测
    fi
}

# 从备份文件恢复数据库
restore_from_backup_file() {
    local backup_data="$1"
    
    log "恢复数据库..."
    gunzip -c "$backup_data" | docker exec -i morhon-odoo-db psql -U odoo postgres 2>/dev/null || \
    log_warn "数据库恢复失败，将使用空数据库"
}

# 全新部署
deploy_new_instance() {
    log "全新部署茂亨Odoo..."
    
    # 询问域名
    local deployment_type domain use_www
    get_deployment_info_interactive "$deployment_type" "$domain" "$use_www"
    
    # 初始化环境（如果需要）
    check_and_init_environment
    
    # 创建新实例
    create_new_instance "$deployment_type" "$domain" "$use_www"
    
    # 重启Nginx
    systemctl reload nginx
    
    log "部署完成！"
    
    if [ "$deployment_type" = "domain" ]; then
        log "访问地址: https://$domain"
    else
        local server_ip=$(get_server_ip)
        log "访问地址: http://$server_ip"
    fi
    
    log "管理员密码: 查看 $INSTANCE_DIR/.env 文件"
    return 0
}

# 交互式获取部署信息
get_deployment_info_interactive() {
    local -n deployment_type_ref=$1
    local -n domain_ref=$2
    local -n use_www_ref=$3
    
    echo ""
    echo "请输入域名（直接回车将使用本地模式）:"
    read -p "域名: " domain_ref
    
    deployment_type_ref="local"
    use_www_ref="no"
    
    if [ -n "$domain_ref" ]; then
        deployment_type_ref="domain"
        # 自动检测是否带www
            if [[ "$domain_ref" == www.* ]]; then
                use_www_ref="yes"
            fi
            # 原手动选择已替换为自动检测
    fi
}

# 检查并初始化环境
check_and_init_environment() {
    if ! command -v docker &> /dev/null || ! command -v nginx &> /dev/null; then
        read -p "检测到缺少依赖，是否初始化环境？(Y/n): " init_env
        if [[ ! "$init_env" =~ ^[Nn]$ ]]; then
            init_environment
        fi
    fi
}

# 管理脚本部署的实例
manage_script_instance() {
    local choice
    while true; do
        show_management_menu
        read -p "请选择操作 (1-7): " choice
        
        case $choice in
            1) show_instance_status ;;
            2) restart_instance ;;
            3) show_logs ;;
            4) backup_instance ;;
            5) modify_config ;;
            6) check_system_status ;;
            7) return 1 ;;  # 返回主菜单
            *) log_error "无效选择" ;;
        esac
        
        [ "$choice" -eq 7 ] && break
        echo ""
        read -p "按回车键继续..."
    done
    
    return 0
}

# 显示管理菜单
show_management_menu() {
    echo ""
    echo -e "${GREEN}脚本管理实例菜单${NC}"
    echo "实例目录: $INSTANCE_DIR"
    echo ""
    echo "1) 查看实例状态"
    echo "2) 重启实例"
    echo "3) 查看日志"
    echo "4) 备份实例"
    echo "5) 修改配置"
    echo "6) 系统状态检查"
    echo "7) 返回主菜单"
    echo ""
}

# 系统状态检查
check_system_status() {
    echo ""
    echo -e "${CYAN}系统状态检查${NC}"
    echo "===================="
    
    # 检查Docker状态
    echo -e "\n${YELLOW}Docker状态:${NC}"
    if systemctl is-active --quiet docker; then
        echo "✓ Docker服务运行正常"
    else
        echo "✗ Docker服务未运行"
    fi
    
    # 检查Nginx状态
    echo -e "\n${YELLOW}Nginx状态:${NC}"
    if systemctl is-active --quiet nginx; then
        echo "✓ Nginx服务运行正常"
    else
        echo "✗ Nginx服务未运行"
    fi
    
    # 检查容器状态
    echo -e "\n${YELLOW}容器状态:${NC}"
    cd "$INSTANCE_DIR"
    docker-compose ps
    
    # 检查端口占用
    echo -e "\n${YELLOW}端口状态:${NC}"
    if netstat -tlnp | grep -q ":8069"; then
        echo "✓ 端口8069已监听"
    else
        echo "✗ 端口8069未监听"
    fi
    
    if netstat -tlnp | grep -q ":8072"; then
        echo "✓ 端口8072已监听"
    else
        echo "✗ 端口8072未监听"
    fi
    
    # 检查磁盘空间
    echo -e "\n${YELLOW}磁盘空间:${NC}"
    df -h / | tail -1 | awk '{print "根分区: " $3 "/" $2 " (" $5 " 已使用)"}'
    
    # 检查内存使用
    echo -e "\n${YELLOW}内存使用:${NC}"
    free -h | grep "Mem:" | awk '{print "内存: " $3 "/" $2 " (" int($3/$2*100) "% 已使用)"}'
    
    # 检查SSL证书（如果是域名模式）
    if [ -f "$INSTANCE_DIR/.env" ]; then
        local domain=$(grep "^DOMAIN=" "$INSTANCE_DIR/.env" | cut -d'=' -f2)
        if [ -n "$domain" ] && [ "$domain" != "" ]; then
            echo -e "\n${YELLOW}SSL证书状态:${NC}"
            if [ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]; then
                local cert_expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$domain/fullchain.pem" | cut -d= -f2)
                echo "✓ SSL证书存在，到期时间: $cert_expiry"
            else
                echo "✗ SSL证书不存在"
            fi
        fi
    fi
    
    echo ""
}

# 显示实例状态
show_instance_status() {
    echo ""
    echo -e "${CYAN}实例状态:${NC}"
    cd "$INSTANCE_DIR"
    docker-compose ps
    echo ""
    echo -e "${CYAN}卷状态:${NC}"
    docker volume ls | grep -E "($DB_VOLUME_NAME|$ODOO_VOLUME_NAME)"
}

# 重启实例
restart_instance() {
    echo ""
    cd "$INSTANCE_DIR"
    docker-compose restart
    systemctl reload nginx
    log "实例已重启"
}

# 显示日志
show_logs() {
    echo ""
    echo "1) Odoo日志"
    echo "2) 数据库日志"
    echo "3) Nginx日志"
    read -p "选择日志类型 (1-3): " log_type
    
    case $log_type in
        1) cd "$INSTANCE_DIR" && docker-compose logs -f odoo ;;
        2) cd "$INSTANCE_DIR" && docker-compose logs -f db ;;
        3) tail -f /var/log/nginx/error.log ;;
        *) log_error "无效选择" ;;
    esac
}

# 备份实例
backup_instance() {
    echo ""
    local backup_name="backup_$(date '+%Y%m%d_%H%M%S')"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    mkdir -p "$backup_path"
    
    log "开始备份实例..."
    
    # 备份数据库
    log "备份数据库..."
    cd "$INSTANCE_DIR"
    if docker-compose exec -T db pg_dump -U odoo postgres | gzip > "$backup_path/database.sql.gz"; then
        log "数据库备份完成"
    else
        log_error "数据库备份失败"
        return 1
    fi
    
    # 备份配置文件
    log "备份配置文件..."
    cp -r "$INSTANCE_DIR/config" "$backup_path/" 2>/dev/null || true
    cp "$INSTANCE_DIR/docker-compose.yml" "$backup_path/" 2>/dev/null || true
    cp "$INSTANCE_DIR/.env" "$backup_path/" 2>/dev/null || true
    
    # 备份Nginx配置
    if [ -f "/etc/nginx/sites-available/morhon-odoo" ]; then
        cp "/etc/nginx/sites-available/morhon-odoo" "$backup_path/nginx-config" 2>/dev/null || true
    fi
    
    # 创建备份信息文件
    cat > "$backup_path/backup_info.txt" << EOF
备份信息
========
备份时间: $(date '+%Y-%m-%d %H:%M:%S')
脚本版本: 6.2
实例目录: $INSTANCE_DIR
备份类型: 完整备份

包含内容:
- 数据库完整备份 (database.sql.gz)
- Odoo配置文件 (config/)
- Docker Compose配置 (docker-compose.yml)
- 环境变量 (.env)
- Nginx配置 (nginx-config)

恢复方法:
1. 解压备份文件
2. 运行脚本选择"从本地备份恢复"
3. 选择此备份文件
EOF
    
    # 打包备份
    cd "$BACKUP_DIR"
    if tar -czf "${backup_name}.tar.gz" "$backup_name"; then
        rm -rf "$backup_path"
        log "备份完成: $BACKUP_DIR/${backup_name}.tar.gz"
        
        # 显示备份大小
        local backup_size=$(du -h "$BACKUP_DIR/${backup_name}.tar.gz" | cut -f1)
        log "备份文件大小: $backup_size"
        
        return 0
    else
        log_error "备份打包失败"
        return 1
    fi
}

# 修改配置
modify_config() {
    echo ""
    echo "1) 修改管理员密码"
    echo "2) 修改数据库密码"
    echo "3) 修改Nginx配置"
    read -p "选择操作 (1-3): " config_choice
    
    case $config_choice in
        1) update_admin_password ;;
        2) update_db_password ;;
        3) update_nginx_config ;;
        *) log_error "无效选择" ;;
    esac
}

# 更新管理员密码
update_admin_password() {
    read -p "输入新管理员密码: " new_pass
    sed -i "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$new_pass/" "$INSTANCE_DIR/.env"
    cd "$INSTANCE_DIR" && docker-compose restart odoo
    log "管理员密码已更新"
}

# 更新数据库密码
update_db_password() {
    read -p "输入新数据库密码: " new_pass
    sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$new_pass/" "$INSTANCE_DIR/.env"
    cd "$INSTANCE_DIR" && docker-compose restart
    log "数据库密码已更新"
}

# 更新Nginx配置
update_nginx_config() {
    nano /etc/nginx/sites-available/morhon-odoo
    nginx -t && systemctl reload nginx
    log "Nginx配置已更新"
}

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE}   茂亨Odoo管理脚本 v6.2${NC}"
    echo -e "${PURPLE}================================${NC}"
    echo ""
    
    # 根据检测结果显示不同菜单
    case "$DETECTED_INSTANCE_TYPE" in
        "script")
            show_script_instance_menu
            ;;
        "manual")
            show_manual_instance_menu
            ;;
        "none")
            show_no_instance_menu
            ;;
    esac
}

# 显示脚本实例菜单
show_script_instance_menu() {
    echo -e "${GREEN}✓ 检测到脚本管理的实例${NC}"
    echo "实例目录: $INSTANCE_DIR"
    echo ""
    echo "1) 管理实例"
    echo "2) 退出"
    echo ""
    read -p "请选择 (1-2): " choice
    
    case $choice in
        1)
            while manage_script_instance; do
                echo ""
                read -p "按回车键继续..."
            done
            ;;
        2) exit 0 ;;
        *) log_error "无效选择" ;;
    esac
}

# 显示手动实例菜单
show_manual_instance_menu() {
    echo -e "${YELLOW}⚠ 检测到手动部署的实例${NC}"
    echo "Odoo容器: $DETECTED_ODOO_CONTAINER"
    [ -n "$DETECTED_DB_CONTAINER" ] && echo "数据库容器: $DETECTED_DB_CONTAINER"
    [ -n "$DETECTED_DOMAIN" ] && echo "域名: $DETECTED_DOMAIN"
    echo ""
    echo "1) 迁移到脚本管理"
    echo "2) 查看容器信息"
    echo "3) 退出"
    echo ""
    read -p "请选择 (1-3): " choice
    
    case $choice in
        1) migrate_manual_instance ;;
        2) show_container_info ;;
        3) exit 0 ;;
        *) log_error "无效选择" ;;
    esac
}

# 显示容器信息
show_container_info() {
    echo ""
    docker ps -a | grep -E "($DETECTED_ODOO_CONTAINER|$DETECTED_DB_CONTAINER)"
    echo ""
    echo "Odoo配置:"
    docker exec "$DETECTED_ODOO_CONTAINER" cat /etc/odoo/odoo.conf 2>/dev/null || echo "无法读取配置"
}

# 显示无实例菜单
show_no_instance_menu() {
    echo -e "${BLUE}○ 未检测到现有实例${NC}"
    echo ""
    echo "1) 全新部署"
    echo "2) 从备份恢复"
    echo "3) 退出"
    echo ""
    read -p "请选择 (1-3): " choice
    
    case $choice in
        1) deploy_new_instance ;;
        2) restore_from_backup ;;
        3) exit 0 ;;
        *) log_error "无效选择" ;;
    esac
}

# 主函数
main() {
    check_sudo
    
    # 一次性检测所有环境信息
    detect_environment
    
    # 显示主菜单
    show_main_menu
}

# 处理命令行参数
if [ $# -ge 1 ]; then
    case "$1" in
        "init")
            check_sudo
            init_environment
            exit 0
            ;;
        "backup")
            check_sudo
            detect_environment
            if [ "$DETECTED_INSTANCE_TYPE" = "script" ]; then
                backup_instance
            else
                log_error "仅支持脚本管理的实例备份"
            fi
            exit 0
            ;;
        "status")
            check_sudo
            detect_environment
            if [ "$DETECTED_INSTANCE_TYPE" = "script" ]; then
                check_system_status
            elif [ "$DETECTED_INSTANCE_TYPE" = "manual" ]; then
                echo "检测到手动部署实例:"
                show_container_info
            else
                echo "未检测到Odoo实例"
            fi
            exit 0
            ;;
        "restore")
            check_sudo
            detect_environment
            restore_from_backup
            exit 0
            ;;
        "help"|"--help"|"-h")
            echo "茂亨Odoo管理脚本 v6.2"
            echo "专为外贸企业设计的Odoo部署和管理工具"
            echo ""
            echo "用法: $0 [命令]"
            echo ""
            echo "命令:"
            echo "  (无参数)   启动交互式菜单"
            echo "  init       初始化环境（安装Docker、Nginx等依赖）"
            echo "  backup     备份脚本管理的实例"
            echo "  restore    从备份恢复（自动检测同目录备份文件）"
            echo "  status     显示实例状态"
            echo "  help       显示此帮助信息"
            echo ""
            echo "功能特性:"
            echo "  • 单实例部署设计，确保系统稳定性"
            echo "  • 自动检测现有实例（脚本管理/手动部署）"
            echo "  • 支持本地模式和域名模式部署"
            echo "  • 自动SSL证书获取和续期"
            echo "  • 完整的备份和恢复功能"
            echo "  • 手动实例迁移到脚本管理"
            echo "  • 性能优化和安全加固"
            echo "  • 健康检查和状态监控"
            echo "  • Docker卷映射，防止插件冲突"
            echo ""
            echo "运行逻辑:"
            echo "  1. 检测现有实例类型"
            echo "  2. 脚本实例 → 管理菜单（状态、备份、配置等）"
            echo "  3. 手动实例 → 迁移菜单（迁移到脚本管理）"
            echo "  4. 无实例 → 全新部署菜单"
            echo ""
            echo "部署模式:"
            echo "  • 本地模式: 通过服务器IP访问，HTTP协议"
            echo "  • 域名模式: 通过域名访问，自动HTTPS"
            echo ""
            echo "重要说明:"
            echo "  • 单实例设计：一台服务器只能部署一个实例"
            echo "  • 数据卷映射：防止用户误操作和插件冲突"
            echo "  • 禁止自装插件：避免系统不稳定和安全风险"
            echo ""
            echo "目录结构:"
            echo "  • 实例目录: /opt/morhon-odoo"
            echo "  • 备份目录: /var/backups/morhon-odoo"
            echo "  • 日志目录: /var/log/morhon-odoo"
            echo ""
            echo "技术支持: https://github.com/morhon-tech/morhon-odoo"
            exit 0
            ;;
    esac
fi

# 执行主函数
main "$@"
