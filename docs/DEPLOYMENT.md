# QACMF部署指南

本文档提供QACMF框架的完整部署指南，涵盖各种环境和配置选项。

## 目录

- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [Docker部署](#docker部署)
- [Kubernetes部署](#kubernetes部署)
- [生产环境部署](#生产环境部署)
- [高可用配置](#高可用配置)
- [监控和日志](#监控和日志)
- [安全配置](#安全配置)
- [故障排除](#故障排除)

## 系统要求

### 最低配置
- **CPU**: 2核心
- **内存**: 4GB RAM
- **存储**: 20GB可用空间
- **操作系统**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Python**: 3.8或更高版本

### 推荐配置
- **CPU**: 8核心或更多
- **内存**: 16GB RAM或更多
- **存储**: 100GB SSD
- **网络**: 千兆以太网
- **HSM**: 硬件安全模块（生产环境）

### 依赖软件
- Docker 20.10+
- Kubernetes 1.24+
- PostgreSQL 13+ (可选)
- Redis 6.0+ (可选)
- Nginx 1.20+ (反向代理)

## 快速开始

### 1. 获取源码

```bash
git clone https://github.com/qacmf/framework.git
cd framework
```

### 2. 本地开发部署

```bash
# 使用部署脚本
./scripts/deploy.sh local

# 或手动安装
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. 验证安装

```bash
qacmf --version
qacmf health-check
```

## Docker部署

### 基础Docker部署

```bash
# 构建镜像
docker build -f deployments/docker/Dockerfile -t qacmf:latest .

# 运行容器
docker run -d \
  --name qacmf-server \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config:/etc/qacmf \
  qacmf:latest
```

### Docker Compose部署

```yaml
# docker-compose.yml
version: '3.8'

services:
  qacmf:
    build:
      context: .
      dockerfile: deployments/docker/Dockerfile
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config:/etc/qacmf
      - qacmf-data:/var/lib/qacmf
      - qacmf-logs:/var/log/qacmf
    environment:
      - QACMF_CONFIG_PATH=/etc/qacmf/config.yaml
      - QACMF_LOG_LEVEL=INFO
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped
    
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=qacmf
      - POSTGRES_USER=qacmf
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    secrets:
      - db_password
    restart: unless-stopped

volumes:
  qacmf-data:
  qacmf-logs:
  redis-data:
  postgres-data:

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f qacmf
```

### 使用部署脚本

```bash
# Docker部署
./scripts/deploy.sh docker

# 查看状态
./scripts/deploy.sh status

# 查看日志
./scripts/deploy.sh logs
```

## Kubernetes部署

### 基础部署

```bash
# 创建命名空间
kubectl create namespace qacmf-system

# 应用配置
kubectl apply -f deployments/kubernetes/

# 查看状态
kubectl -n qacmf-system get pods
```

### 使用部署脚本

```bash
# Kubernetes部署
./scripts/deploy.sh kubernetes

# 指定环境和命名空间
./scripts/deploy.sh -e production -n qacmf-prod kubernetes
```

### Helm部署

```bash
# 添加Helm仓库
helm repo add qacmf https://charts.qacmf.org
helm repo update

# 安装
helm install qacmf qacmf/qacmf \
  --namespace qacmf-system \
  --create-namespace \
  --values values-production.yaml
```

### 自定义配置

```yaml
# values-production.yaml
replicaCount: 3

image:
  repository: qacmf/framework
  tag: "2.0.0"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8080
  httpsPort: 8443

ingress:
  enabled: true
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: qacmf.company.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: qacmf-tls
      hosts:
        - qacmf.company.com

resources:
  requests:
    cpu: 1000m
    memory: 2Gi
  limits:
    cpu: 2000m
    memory: 4Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

persistence:
  enabled: true
  storageClass: fast-ssd
  size: 10Gi

hsm:
  enabled: true
  configSecret: qacmf-hsm-config

monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
  grafana:
    dashboards:
      enabled: true
```

## 生产环境部署

### 1. 环境准备

```bash
# 安装系统依赖
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  libssl-dev \
  libffi-dev \
  python3-dev \
  pkg-config

# 创建专用用户
sudo useradd -r -s /bin/false qacmf
sudo mkdir -p /opt/qacmf/{config,keys,logs}
sudo chown -R qacmf:qacmf /opt/qacmf
```

### 2. 配置管理

```bash
# 复制生产配置
cp config/production.yaml /opt/qacmf/config/

# 设置权限
sudo chmod 600 /opt/qacmf/config/*.yaml
sudo chown qacmf:qacmf /opt/qacmf/config/*.yaml
```

### 3. 系统服务

```ini
# /etc/systemd/system/qacmf.service
[Unit]
Description=QACMF Quantum-Safe Cryptography Framework
After=network.target
Wants=network.target

[Service]
Type=forking
User=qacmf
Group=qacmf
WorkingDirectory=/opt/qacmf
Environment=QACMF_CONFIG_PATH=/opt/qacmf/config/production.yaml
ExecStart=/opt/qacmf/bin/qacmf start --daemon
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
PIDFile=/var/run/qacmf/qacmf.pid
Restart=always
RestartSec=10

# 安全限制
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/qacmf /var/run/qacmf /var/log/qacmf

[Install]
WantedBy=multi-user.target
```

```bash
# 启用服务
sudo systemctl daemon-reload
sudo systemctl enable qacmf
sudo systemctl start qacmf

# 查看状态
sudo systemctl status qacmf
```

### 4. 负载均衡配置

```nginx
# /etc/nginx/sites-available/qacmf
upstream qacmf_backend {
    least_conn;
    server 10.0.1.10:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    listen [::]:80;
    server_name qacmf.company.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name qacmf.company.com;

    # SSL配置
    ssl_certificate /etc/ssl/certs/qacmf.crt;
    ssl_certificate_key /etc/ssl/private/qacmf.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    # 安全头
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        proxy_pass http://qacmf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 超时设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # 缓冲设置
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    location /health {
        access_log off;
        proxy_pass http://qacmf_backend/health;
    }

    location /metrics {
        access_log off;
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://qacmf_backend/metrics;
    }
}
```

## 高可用配置

### 1. 数据库集群

```yaml
# PostgreSQL高可用配置
postgresql:
  replication:
    enabled: true
    master:
      host: db-master.company.com
      port: 5432
    slaves:
      - host: db-slave-1.company.com
        port: 5432
      - host: db-slave-2.company.com
        port: 5432
  
  failover:
    enabled: true
    detection_timeout: 30s
    automatic: true
```

### 2. Redis集群

```yaml
# Redis集群配置
redis:
  cluster:
    enabled: true
    nodes:
      - redis-1.company.com:6379
      - redis-2.company.com:6379
      - redis-3.company.com:6379
      - redis-4.company.com:6379
      - redis-5.company.com:6379
      - redis-6.company.com:6379
```

### 3. 共享存储

```yaml
# 共享存储配置
storage:
  type: nfs
  server: storage.company.com
  path: /exports/qacmf
  options: "rw,sync,hard,intr"
```

## 监控和日志

### 1. Prometheus监控

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'qacmf'
    static_configs:
      - targets: ['qacmf-1:8080', 'qacmf-2:8080', 'qacmf-3:8080']
    metrics_path: /metrics
    scrape_interval: 30s
```

### 2. Grafana仪表盘

```json
{
  "dashboard": {
    "title": "QACMF监控仪表盘",
    "panels": [
      {
        "title": "请求率",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(qacmf_http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "响应时间",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, qacmf_http_request_duration_seconds_bucket)"
          }
        ]
      },
      {
        "title": "密钥操作",
        "type": "graph",
        "targets": [
          {
            "expr": "qacmf_key_operations_total"
          }
        ]
      }
    ]
  }
}
```

### 3. 日志聚合

```yaml
# ELK配置
filebeat:
  inputs:
    - type: log
      paths:
        - /var/log/qacmf/*.log
      fields:
        service: qacmf
        environment: production

logstash:
  pipeline:
    - input:
        beats:
          port: 5044
    - filter:
        grok:
          match:
            message: "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}"
    - output:
        elasticsearch:
          hosts: ["elasticsearch:9200"]
          index: "qacmf-logs-%{+YYYY.MM.dd}"
```

## 安全配置

### 1. 网络安全

```bash
# 防火墙配置
sudo ufw allow from 10.0.0.0/8 to any port 8080
sudo ufw allow from 10.0.0.0/8 to any port 8443
sudo ufw deny 8080
sudo ufw deny 8443
sudo ufw enable
```

### 2. HSM配置

```json
{
  "hsm": {
    "vendor": "Thales",
    "model": "Luna HSM 7",
    "slots": {
      "master_key": {
        "slot_id": 0,
        "partition": "qacmf-master",
        "password_file": "/etc/qacmf/secrets/hsm-master.pass"
      },
      "session_keys": {
        "slot_id": 1,
        "partition": "qacmf-session",
        "password_file": "/etc/qacmf/secrets/hsm-session.pass"
      }
    },
    "failover": {
      "enabled": true,
      "backup_hsm": "10.0.1.100"
    }
  }
}
```

### 3. 证书管理

```bash
# 生成CA证书
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# 生成服务证书
openssl genrsa -out qacmf.key 2048
openssl req -new -key qacmf.key -out qacmf.csr
openssl x509 -req -in qacmf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out qacmf.crt -days 365
```

## 故障排除

### 常见问题

#### 1. 服务启动失败

```bash
# 检查配置文件
qacmf config validate

# 检查端口占用
sudo netstat -tlnp | grep :8080

# 查看详细日志
journalctl -u qacmf -f
```

#### 2. HSM连接问题

```bash
# 检查HSM状态
/opt/safenet/lunaclient/bin/lunacm
LunaCM> slot list

# 测试连接
qacmf hsm test-connection
```

#### 3. 性能问题

```bash
# 检查系统资源
top
iotop
nethogs

# 分析性能瓶颈
qacmf benchmark
```

#### 4. 内存泄露

```bash
# 监控内存使用
ps aux | grep qacmf
cat /proc/$(pgrep qacmf)/status

# 生成内存转储
kill -USR1 $(pgrep qacmf)
```

### 日志分析

```bash
# 查看错误日志
grep ERROR /var/log/qacmf/qacmf.log

# 统计请求
awk '/HTTP/ {print $7}' /var/log/qacmf/access.log | sort | uniq -c

# 监控关键指标
tail -f /var/log/qacmf/qacmf.log | grep -E "(ERROR|WARN|key_rotation)"
```

### 性能调优

```yaml
# 生产环境性能调优
performance:
  threading:
    worker_threads: 32      # 增加工作线程
    io_threads: 16          # 增加IO线程
    
  memory:
    max_heap_size: "16G"    # 增加堆内存
    gc_threads: 8           # 垃圾回收线程
    
  crypto:
    batch_size: 1000        # 批处理大小
    cache_size: 10000       # 缓存大小
```

## 备份和恢复

### 1. 数据备份

```bash
# 自动备份脚本
./scripts/deploy.sh backup

# 手动备份
qacmf backup create --type full --output /backup/qacmf-$(date +%Y%m%d).tar.gz
```

### 2. 数据恢复

```bash
# 恢复数据
./scripts/deploy.sh restore

# 指定备份文件
qacmf backup restore --file /backup/qacmf-20231201.tar.gz
```

### 3. 灾难恢复

```bash
# 灾难恢复计划
1. 评估损坏程度
2. 启动备用环境
3. 恢复最新备份
4. 验证服务功能
5. 切换DNS指向
6. 监控系统状态
```

有关更多详细信息，请参阅[官方文档](https://docs.qacmf.org)。 