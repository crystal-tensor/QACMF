# 多阶段构建，优化镜像大小
FROM python:3.11-slim as builder

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    pkg-config \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY pyproject.toml ./
COPY README.md ./

# 安装Python依赖
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir build

# 复制源代码
COPY src/ ./src/

# 构建包
RUN python -m build

# 运行时镜像
FROM python:3.11-slim as runtime

# 创建非特权用户
RUN groupadd -r qacmf && useradd -r -g qacmf qacmf

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 从构建阶段复制包
COPY --from=builder /app/dist/*.whl ./

# 安装QACMF
RUN pip install --no-cache-dir *.whl && \
    rm -f *.whl

# 创建配置目录
RUN mkdir -p /etc/qacmf /var/log/qacmf /var/lib/qacmf && \
    chown -R qacmf:qacmf /etc/qacmf /var/log/qacmf /var/lib/qacmf

# 复制默认配置
COPY config/default.yaml /etc/qacmf/config.yaml
COPY config/hsm-config.json /etc/qacmf/hsm-config.json

# 修改配置文件权限
RUN chown -R qacmf:qacmf /etc/qacmf

# 切换到非特权用户
USER qacmf

# 暴露端口
EXPOSE 8080 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import qacmf; print('OK')" || exit 1

# 设置环境变量
ENV QACMF_CONFIG_PATH=/etc/qacmf/config.yaml
ENV QACMF_LOG_LEVEL=INFO
ENV PYTHONPATH=/app

# 默认命令
CMD ["qacmf", "start", "--config", "/etc/qacmf/config.yaml"]