#!/bin/bash
# QACMF部署脚本
# 用于自动化部署QACMF框架到各种环境

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION=$(grep version pyproject.toml | head -1 | cut -d'"' -f2)
NAMESPACE="qacmf-system"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-qacmf}"
ENVIRONMENT="${ENVIRONMENT:-development}"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
QACMF部署脚本

用法: $0 [选项] [命令]

命令:
    docker          构建并部署Docker容器
    kubernetes      部署到Kubernetes集群
    local           本地开发环境部署
    clean           清理部署资源
    status          查看部署状态
    logs            查看应用日志
    backup          备份配置和数据
    restore         恢复配置和数据

选项:
    -e, --env ENV          指定环境 (development/staging/production)
    -n, --namespace NS     指定Kubernetes命名空间
    -r, --registry REG     指定Docker镜像仓库
    -v, --version VER      指定版本号
    -h, --help             显示此帮助信息

示例:
    $0 docker                    # 部署到Docker
    $0 -e production kubernetes  # 部署到生产Kubernetes
    $0 local                     # 本地开发部署
    $0 clean                     # 清理资源

EOF
}

# 检查依赖
check_dependencies() {
    log_info "检查部署依赖..."
    
    local missing_deps=()
    
    # 检查Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    # 检查kubectl（如果部署到Kubernetes）
    if [[ "$1" == "kubernetes" ]] && ! command -v kubectl &> /dev/null; then
        missing_deps+=("kubectl")
    fi
    
    # 检查Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        exit 1
    fi
    
    log_success "依赖检查通过"
}

# 构建Docker镜像
build_docker_image() {
    log_info "构建Docker镜像..."
    
    cd "$PROJECT_ROOT"
    
    # 构建镜像
    docker build \
        -f deployments/docker/Dockerfile \
        -t "${DOCKER_REGISTRY}/framework:${VERSION}" \
        -t "${DOCKER_REGISTRY}/framework:latest" \
        .
    
    log_success "Docker镜像构建完成"
}

# 推送Docker镜像
push_docker_image() {
    log_info "推送Docker镜像到仓库..."
    
    docker push "${DOCKER_REGISTRY}/framework:${VERSION}"
    docker push "${DOCKER_REGISTRY}/framework:latest"
    
    log_success "Docker镜像推送完成"
}

# Docker部署
deploy_docker() {
    log_info "开始Docker部署..."
    
    check_dependencies "docker"
    build_docker_image
    
    # 停止现有容器
    docker stop qacmf-server 2>/dev/null || true
    docker rm qacmf-server 2>/dev/null || true
    
    # 创建网络（如果不存在）
    docker network create qacmf-network 2>/dev/null || true
    
    # 启动容器
    docker run -d \
        --name qacmf-server \
        --network qacmf-network \
        -p 8080:8080 \
        -p 8443:8443 \
        -v "${PROJECT_ROOT}/config:/etc/qacmf" \
        -v "qacmf-data:/var/lib/qacmf" \
        -v "qacmf-logs:/var/log/qacmf" \
        -e QACMF_CONFIG_PATH=/etc/qacmf/config.yaml \
        -e QACMF_LOG_LEVEL=INFO \
        -e ENVIRONMENT="$ENVIRONMENT" \
        "${DOCKER_REGISTRY}/framework:${VERSION}"
    
    log_success "Docker部署完成"
    log_info "服务地址: http://localhost:8080"
}

# Kubernetes部署
deploy_kubernetes() {
    log_info "开始Kubernetes部署..."
    
    check_dependencies "kubernetes"
    
    # 检查集群连接
    if ! kubectl cluster-info &> /dev/null; then
        log_error "无法连接到Kubernetes集群"
        exit 1
    fi
    
    # 构建并推送镜像
    build_docker_image
    push_docker_image
    
    # 创建命名空间
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # 应用配置
    envsubst < deployments/kubernetes/qacmf-deployment.yaml | kubectl apply -f -
    
    # 等待部署完成
    kubectl -n "$NAMESPACE" rollout status deployment/qacmf-server --timeout=300s
    
    log_success "Kubernetes部署完成"
    
    # 显示服务信息
    kubectl -n "$NAMESPACE" get services
}

# 本地开发部署
deploy_local() {
    log_info "开始本地开发环境部署..."
    
    cd "$PROJECT_ROOT"
    
    # 检查Python环境
    if [[ ! -d ".venv" ]]; then
        log_info "创建虚拟环境..."
        python3 -m venv .venv
    fi
    
    # 激活虚拟环境
    source .venv/bin/activate
    
    # 安装依赖
    log_info "安装依赖..."
    pip install --upgrade pip
    pip install -e .
    pip install -r requirements-dev.txt
    
    # 创建配置目录
    mkdir -p ~/.qacmf/{config,keys,logs}
    
    # 复制默认配置
    if [[ ! -f ~/.qacmf/config/config.yaml ]]; then
        cp config/default.yaml ~/.qacmf/config/config.yaml
        log_info "已复制默认配置到 ~/.qacmf/config/"
    fi
    
    # 启动服务
    log_info "启动QACMF服务..."
    nohup qacmf start --config ~/.qacmf/config/config.yaml > ~/.qacmf/logs/qacmf.log 2>&1 &
    
    log_success "本地开发环境部署完成"
    log_info "服务地址: http://localhost:8080"
    log_info "日志文件: ~/.qacmf/logs/qacmf.log"
}

# 清理资源
clean_deployment() {
    log_info "清理部署资源..."
    
    # Docker清理
    if command -v docker &> /dev/null; then
        docker stop qacmf-server 2>/dev/null || true
        docker rm qacmf-server 2>/dev/null || true
        docker rmi "${DOCKER_REGISTRY}/framework:${VERSION}" 2>/dev/null || true
        docker network rm qacmf-network 2>/dev/null || true
        log_info "Docker资源已清理"
    fi
    
    # Kubernetes清理
    if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
        kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
        log_info "Kubernetes资源已清理"
    fi
    
    # 本地进程清理
    pkill -f "qacmf start" 2>/dev/null || true
    
    log_success "资源清理完成"
}

# 查看部署状态
check_status() {
    log_info "检查部署状态..."
    
    # Docker状态
    if command -v docker &> /dev/null; then
        echo "=== Docker 容器状态 ==="
        docker ps --filter name=qacmf-server --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || true
        echo
    fi
    
    # Kubernetes状态
    if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
        echo "=== Kubernetes 部署状态 ==="
        kubectl -n "$NAMESPACE" get pods,services,deployments 2>/dev/null || true
        echo
    fi
    
    # 本地进程状态
    echo "=== 本地进程状态 ==="
    pgrep -f "qacmf start" && echo "QACMF进程正在运行" || echo "QACMF进程未运行"
    echo
    
    # 健康检查
    echo "=== 服务健康检查 ==="
    if curl -sf http://localhost:8080/health &> /dev/null; then
        log_success "服务健康检查通过"
    else
        log_warning "服务健康检查失败"
    fi
}

# 查看日志
view_logs() {
    log_info "查看应用日志..."
    
    case "$ENVIRONMENT" in
        "docker")
            docker logs -f qacmf-server
            ;;
        "kubernetes")
            kubectl -n "$NAMESPACE" logs -f deployment/qacmf-server
            ;;
        "local"|*)
            tail -f ~/.qacmf/logs/qacmf.log 2>/dev/null || \
            tail -f /var/log/qacmf/qacmf.log 2>/dev/null || \
            log_error "找不到日志文件"
            ;;
    esac
}

# 备份配置和数据
backup_data() {
    log_info "备份配置和数据..."
    
    local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # 备份配置文件
    if [[ -d "config" ]]; then
        cp -r config "$backup_dir/"
        log_info "已备份配置文件"
    fi
    
    # 备份Kubernetes配置
    if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
        kubectl -n "$NAMESPACE" get all -o yaml > "$backup_dir/kubernetes-resources.yaml" 2>/dev/null || true
        log_info "已备份Kubernetes资源"
    fi
    
    # 备份数据卷
    if command -v docker &> /dev/null; then
        docker run --rm \
            -v qacmf-data:/data \
            -v "$(pwd)/$backup_dir:/backup" \
            busybox tar czf /backup/qacmf-data.tar.gz -C /data . 2>/dev/null || true
        log_info "已备份Docker数据卷"
    fi
    
    log_success "备份完成: $backup_dir"
}

# 恢复配置和数据
restore_data() {
    log_info "恢复配置和数据..."
    
    # 列出可用备份
    if [[ -d "backups" ]]; then
        echo "可用备份:"
        ls -la backups/
        read -p "请输入要恢复的备份目录名: " backup_name
        
        if [[ -d "backups/$backup_name" ]]; then
            # 恢复配置
            if [[ -d "backups/$backup_name/config" ]]; then
                cp -r "backups/$backup_name/config" .
                log_info "已恢复配置文件"
            fi
            
            # 恢复数据卷
            if [[ -f "backups/$backup_name/qacmf-data.tar.gz" ]]; then
                docker run --rm \
                    -v qacmf-data:/data \
                    -v "$(pwd)/backups/$backup_name:/backup" \
                    busybox tar xzf /backup/qacmf-data.tar.gz -C /data
                log_info "已恢复Docker数据卷"
            fi
            
            log_success "数据恢复完成"
        else
            log_error "备份目录不存在: $backup_name"
            exit 1
        fi
    else
        log_error "没有找到备份目录"
        exit 1
    fi
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -r|--registry)
                DOCKER_REGISTRY="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            docker|kubernetes|local|clean|status|logs|backup|restore)
                COMMAND="$1"
                shift
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 主函数
main() {
    # 显示部署信息
    log_info "QACMF部署脚本"
    log_info "版本: $VERSION"
    log_info "环境: $ENVIRONMENT"
    log_info "命名空间: $NAMESPACE"
    echo
    
    # 执行命令
    case "${COMMAND:-}" in
        docker)
            deploy_docker
            ;;
        kubernetes)
            deploy_kubernetes
            ;;
        local)
            deploy_local
            ;;
        clean)
            clean_deployment
            ;;
        status)
            check_status
            ;;
        logs)
            view_logs
            ;;
        backup)
            backup_data
            ;;
        restore)
            restore_data
            ;;
        *)
            log_error "请指定部署命令"
            show_help
            exit 1
            ;;
    esac
}

# 解析参数并执行
parse_args "$@"
main 