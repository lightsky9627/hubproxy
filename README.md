# HubProxy - 专为容器镜像打造的高性能防滥用代理加速器

HubProxy 是基于 Go 语言开发的容器镜像（Docker Registry v2）透明代理与加速网关。内置 Web 镜像搜索、离线打包下载、多用户配额体系、官方 Docker Hub 账号池透传/托管、拉取日志审计以及管理员后台管理。

---

## 📥 二进制下载

编译产物会自动发布至 GitHub 仓库：
- **GitHub Releases**：直接前往 [Releases 页面](https://github.com/lightsky9627/hubproxy/releases) 下载最新版本的 `hubproxy-linux-amd64.tar.gz` 或 `hubproxy-linux-arm64.tar.gz`。
- **Actions Artifacts**：在每次 commit 的 [Actions 页面](https://github.com/lightsky9627/hubproxy/actions) 底部也可以直接下载打包的 Artifacts。

---

## 🛠️ 部署与服务管理

下载二进制文件后，将其放置于 `/usr/local/bin/hubproxy`：
```bash
chmod +x hubproxy-linux-amd64
sudo mv hubproxy-linux-amd64 /usr/local/bin/hubproxy

# 创建工作目录与数据目录
sudo mkdir -p /etc/hubproxy/data
sudo cp src/config.toml /etc/hubproxy/config.toml
```

### 1. Systemd 服务管理（Debian / Ubuntu / CentOS / Rocky Linux）

1. 复制 service 文件：
   ```bash
   sudo cp packaging/systemd/hubproxy.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```
2. 管理命令：
   ```bash
   sudo systemctl enable --now hubproxy  # 开机自启并立即启动
   sudo systemctl status hubproxy        # 查看运行状态
   sudo systemctl restart hubproxy       # 重启服务
   journalctl -u hubproxy -f             # 实时查看日志
   ```

### 2. Alpine Linux (OpenRC 管理)

Alpine Linux 默认使用 OpenRC 进行服务管理：
1. 复制 init.d 脚本并赋予执行权限：
   ```bash
   cp packaging/openrc/hubproxy.initd /etc/init.d/hubproxy
   chmod +x /etc/init.d/hubproxy
   ```
2. 管理命令：
   ```bash
   rc-update add hubproxy default   # 添加开机自启
   rc-service hubproxy start        # 启动服务
   rc-service hubproxy status       # 查看状态
   rc-service hubproxy restart      # 重启服务
   ```
3. 查看日志：
   ```bash
   tail -f /var/log/hubproxy.log
   ```

---

## ✨ 核心特性

- 🐳 **专注容器镜像** - 全面适配 Docker Registry v2 协议，支持 Docker Hub、GHCR、Quay、GCR、K8s 等多种镜像仓库。
- 🛡️ **严格防滥用机制** -
  - **独立用户与配额**：支持在后台管理为不同团队/人员分配账号，支持自然月拉取次数限额控制。
  - **匿名拉取限流**：支持设置是否允许未登录匿名拉取，以及按 IP 限制匿名每月拉取额度。
  - **Docker Hub 上游账号池托管**：可在后台配置官方付费/高配额账号，客户端拉取时服务端使用托管账号向上游拿镜像，彻底隐藏上游凭据。
  - **官方账号透传**：支持未在本地注册的 Docker Hub 账号凭据直接透传认证。
- 📊 **可视化后台与审计** - 内置 `/admin` 管理后台，实时统计拉取数据，完整记录拉取时间、账号、客户端 IP、镜像名与耗时。
- 🔍 **Web 镜像搜索与打包** - 纯浏览器在线搜索 Docker Hub 镜像与 Tag，支持单镜像/多镜像一键离线 tar 包流式打包下载。
- ⚡ **单裸二进制部署** - 基于嵌入式 SQLite，无须搭建外部数据库，单二进制即拷即用，兼容 Alpine、Debian、CentOS、Rocky 等。

---

## 🛠️ 快速启动

### 裸二进制运行（推荐）

1. 启动服务：
   ```bash
   ./hubproxy
   ```
2. 浏览器访问：
   - 镜像搜索：`http://<IP>:5000`
   - 管理后台：`http://<IP>:5000/admin`（默认账号：`admin`，默认密码：`admin123456`）

### Docker Compose 启动

```bash
docker compose up -d
```

---

## 💻 客户端 Docker 使用指引

### 1. 登录自建代理站
在后台管理为用户创建账号（例如 `user1` / `pass123`）后，在客户端终端登录：
```bash
docker login <your-domain> -u user1 -p pass123
```

### 2. 拉取 Docker Hub 官方镜像
```bash
docker pull <your-domain>/nginx:latest
docker pull <your-domain>/library/redis:alpine
```

### 3. 拉取其他镜像仓库 (如 ghcr.io / quay.io)
```bash
docker pull <your-domain>/ghcr.io/owner/repo:latest
docker pull <your-domain>/quay.io/coreos/etcd:latest
```

---

## ⚙️ Nginx 反向代理配置参考

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name hub.yourdomain.com;

    # SSL 证书配置
    # ssl_certificate /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;

    client_max_body_size 0;
    chunked_transfer_encoding on;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
```

---

## 📦 CI/CD 持续集成

- **GitLab CI**：配置了 `.gitlab-ci.yml`，自动构建 Linux AMD64 和 ARM64 静态二进制包。
- **GitHub Actions**：配置了 `.github/workflows/build.yml`。

## 详细文档

[中文文档](https://zread.ai/sky22333/hubproxy)

[English](https://deepwiki.com/sky22333/hubproxy)

## 快速开始

### Docker部署（推荐）
```
docker run -d \
  --name hubproxy \
  -p 5000:5000 \
  --restart always \
  ghcr.io/sky22333/hubproxy
```

### 脚本安装

自动识别系统与架构，从 GitHub Releases 下载对应的 `.deb`、`.rpm` 或 `.apk` 安装包：

```bash
curl -fsSL https://raw.githubusercontent.com/sky22333/hubproxy/main/install.sh | sh
```

安装包会自动安装并启动 `hubproxy` 服务。

<details>
  <summary>服务管理命令</summary>

#### systemd（Debian / Ubuntu / RHEL / CentOS / Fedora）

```bash
# 查看状态
sudo systemctl status hubproxy

# 重启服务
sudo systemctl restart hubproxy

# 查看实时日志
sudo journalctl -u hubproxy -f

# 编辑配置文件
sudo nano /etc/hubproxy/config.toml

# 卸载服务
sudo apt remove hubproxy

# 连配置一起清理
sudo apt purge hubproxy
```

#### OpenRC（Alpine Linux）

```bash
# 查看状态
sudo rc-service hubproxy status

# 重启服务
sudo rc-service hubproxy restart

# 查看实时日志
sudo tail -f /var/log/hubproxy.log

# 编辑配置文件
sudo vi /etc/hubproxy/config.toml

# 卸载
sudo apk del hubproxy
```

</details>

### 文件路径

- Linux 安装包配置文件：`/etc/hubproxy/config.toml`
- Linux 安装包二进制文件：`/usr/bin/hubproxy`
- systemd 服务文件：`/lib/systemd/system/hubproxy.service`
- Alpine OpenRC 服务文件：`/etc/init.d/hubproxy`
- Alpine 日志文件：`/var/log/hubproxy.log`
- Alpine 日志轮转配置：`/etc/logrotate.d/hubproxy`

## 使用方法

### Docker 镜像加速

```bash
# 原命令
docker pull nginx

# 使用加速
docker pull yourdomain.com/nginx

# ghcr加速
docker pull yourdomain.com/ghcr.io/sky22333/hubproxy

# 符合Docker Registry API v2标准的仓库都支持
```

当然也支持配置为全局镜像加速，在主机上新建（或编辑）`/etc/docker/daemon.json`

在 `"registry-mirrors"` 中加入域名：

```json
{
  "registry-mirrors": [
    "https://yourdomain.com"
  ]
}
```

若已设置其他加速地址，直接并列添加后保存，再执行 `sudo systemctl restart docker` 重启docker服务让配置生效。

### GitHub 文件加速

```bash
# 原链接
https://github.com/user/repo/releases/download/v1.0.0/file.tar.gz

# 加速链接
https://yourdomain.com/https://github.com/user/repo/releases/download/v1.0.0/file.tar.gz

# 加速下载仓库
git clone https://yourdomain.com/https://github.com/sky22333/hubproxy.git
```

## 配置

<details>
  <summary>config.toml 配置说明</summary>

*此配置是默认配置，已经内置在程序中了*

```
[server]
host = "0.0.0.0"
# 监听端口
port = 5000
# Github文件大小限制（字节），默认2GB
fileSize = 2147483648
# HTTP/2 多路复用，提升下载速度
enableH2C = false
# 是否启用前端静态页面
enableFrontend = true

[rateLimit]
# 每个IP每周期允许的请求数(注意Docker镜像会有多个层，会消耗多个次数)
requestLimit = 500
# 限流周期（小时）
periodHours = 3.0

[security]
# IP白名单，支持单个IP或IP段
# 白名单中的IP不受限流限制
whiteList = [
    "127.0.0.1",
    "172.17.0.0/16",
    "192.168.1.0/24"
]

# IP黑名单，支持单个IP或IP段
# 黑名单中的IP将被直接拒绝访问
blackList = [
    "192.168.100.1",
    "192.168.100.0/24"
]

[access]
# 代理服务白名单（支持GitHub仓库和Docker镜像，支持通配符）
# 只允许访问白名单中的仓库/镜像，为空时不限制
whiteList = []

# 代理服务黑名单（支持GitHub仓库和Docker镜像，支持通配符）
# 禁止访问黑名单中的仓库/镜像
blackList = [
    "baduser/malicious-repo",
    "*/malicious-repo",
    "baduser/*"
]

# 代理配置，支持有用户名/密码认证和无认证模式
# 无认证: socks5://127.0.0.1:1080
# 有认证: socks5://username:password@127.0.0.1:1080
# 留空不使用代理
proxy = "" 

[download]
# 批量下载离线镜像数量限制
maxImages = 10

# Registry映射配置，支持多种镜像仓库上游
[registries]

# GitHub Container Registry
[registries."ghcr.io"]
upstream = "ghcr.io"
authHost = "ghcr.io/token" 
authType = "github"
enabled = true

# Google Container Registry
[registries."gcr.io"]
upstream = "gcr.io"
authHost = "gcr.io/v2/token"
authType = "google"
enabled = true

# Quay.io Container Registry
[registries."quay.io"]
upstream = "quay.io"
authHost = "quay.io/v2/auth"
authType = "quay"
enabled = true

# Kubernetes Container Registry
[registries."registry.k8s.io"]
upstream = "registry.k8s.io"
authHost = "registry.k8s.io"
authType = "anonymous"
enabled = true

[tokenCache]
# 是否启用缓存(同时控制Token和Manifest缓存)显著提升性能
enabled = true
# 默认缓存时间(分钟)
defaultTTL = "20m"
```

</details>

### 环境变量（可选）

支持通过环境变量覆盖部分配置，优先级高于`config.toml`，以下是默认值：

```
CONFIG_PATH=config.toml          # 配置文件路径
SERVER_HOST=0.0.0.0             # 监听地址
SERVER_PORT=5000                # 监听端口
ENABLE_H2C=false                # 是否启用 H2C
ENABLE_FRONTEND=true            # 是否启用前端静态页面
MAX_FILE_SIZE=2147483648        # GitHub 文件大小限制（字节）
RATE_LIMIT=500                  # 每周期请求数
RATE_PERIOD_HOURS=3             # 限流周期（小时）
IP_WHITELIST=127.0.0.1,192.168.1.0/24   # IP 白名单（逗号分隔）
IP_BLACKLIST=192.168.100.1,192.168.100.0/24 # IP 黑名单（逗号分隔）
MAX_IMAGES=10                   # 批量下载镜像数量限制
ACCESS_PROXY=                   # 代理配置，例如 socks5://127.0.0.1:1080
```

为了IP限流能够正常运行，反向代理需要传递IP头用来获取访客真实IP，以caddy为例：
```
example.com {
    reverse_proxy {
        to 127.0.0.1:5000
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
```
cloudflare CDN：
```
example.com {
    reverse_proxy 127.0.0.1:5000 {
        header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}
        header_up X-Real-IP {http.request.header.CF-Connecting-IP}
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Host {host}
    }
}
```

> 对于使用nginx反代的用户，Github加速提示`无效输入`的问题可以参见[issues/62](https://github.com/sky22333/hubproxy/issues/62#issuecomment-3219572440)


## ⚠️ 免责声明

- 本程序仅供学习交流使用，请勿用于非法用途
- 使用本程序需遵守当地法律法规
- 作者不对使用者的任何行为承担责任

---

<div align="center">

**⭐ 如果这个项目对你有帮助，请给个 Star！⭐**

</div>

## 界面预览

![1](./.github/demo/demo1.jpg)

## Star 趋势
[![Star 趋势](https://starchart.cc/sky22333/hubproxy.svg?variant=adaptive)](https://starchart.cc/sky22333/hubproxy)
