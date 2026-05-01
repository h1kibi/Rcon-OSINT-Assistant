# Rcon-OSINT-Assistant

<div align="center">

**漏洞情报侦察兵 — 本地漏洞情报自动收集、评分、分析桌面工具**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![PySide6](https://img.shields.io/badge/PySide6-6.6+-green.svg)](https://doc.qt.io/qtforpython-6/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 项目简介

Rcon 是一款本地运行的漏洞情报桌面应用，自动从多个权威数据源收集最新漏洞情报，进行标准化、去重、评分和排序，帮助安全团队快速识别高价值漏洞并优先处置。

**核心特性：**
- 🤖 像素风机器人悬浮球，动态眨眼动画
- 📊 多源情报自动采集（NVD、CISA KEV、EPSS、GitHub Advisory 等 13+ 数据源）
- 🧠 智能评分系统，综合 KEV/EPSS/CVSS/PoC/时效性等多维度
- 🔍 AI 漏洞分析，支持联网搜索获取一手情报
- 📁 个人库管理，关注漏洞自动归档
- 🌙 黑客风格深色 UI，极客感十足

---

## 功能特性

### 悬浮球
- 像素风机器人头设计，黑绿配色
- 绿色眼睛呼吸光效 + 周期性眨眼动画
- 红色未读数字脉冲动画
- 支持拖拽移动
- 左键打开主面板，右键弹出菜单

### 漏洞列表
- 按处置价值评分排序展示
- 支持多种排序：默认智能推荐 / 评分 / 发布时间 / CVSS
- 筛选功能：KEV / 高危 / EPSS高 / PoC / 有补丁
- 时间筛选：24小时 / 3天 / 7天 / 30天 / 全部
- 来源筛选：NVD / CISA KEV / GitHub Advisory 等
- 关键词搜索：支持 CVE ID / GHSA ID / 标题 / 描述

### 漏洞详情
- 独立弹窗展示完整漏洞信息
- CVSS / EPSS / KEV / PoC / 补丁状态
- 影响产品和版本信息
- 评分依据详细解释
- 参考链接可点击
- 一键保存漏洞描述到本地

### AI 分析
- 接入 OpenAI / Anthropic 兼容协议
- 自动联网搜索获取一手情报
- Markdown 渲染输出（表格、代码块、标题）
- 暂停 / 继续分析功能
- 分析结果自动保存到本地文件夹
- 分析后自动关注漏洞入个人库
- 历史分析记录查看

### 个人库
- 关注的漏洞自动归档
- AI 分析过的漏洞自动加入
- 每个漏洞独立文件夹存放分析记录
- 支持查看历史分析

### 数据源

| 数据源 | 说明 | 默认状态 |
|--------|------|----------|
| NVD | 官方 CVE 数据库 | ✅ 启用 |
| CISA KEV | 已知被利用漏洞目录 | ✅ 启用 |
| EPSS | 漏洞利用预测评分 | ✅ 启用 |
| GitHub Advisory | 开源生态漏洞 | ✅ 启用 |
| CISA RSS | 安全通告 RSS | ✅ 启用 |
| Ubuntu | Ubuntu 安全通告 | ✅ 启用 |
| Red Hat | Red Hat 安全数据 | ✅ 启用 |
| Debian | Debian 安全追踪 | ✅ 启用 |
| OSV.dev | 开源组件漏洞 | ✅ 启用 |
| MSRC | 微软安全更新 | ❌ 需配置 |
| Cisco PSIRT | Cisco 安全公告 | ❌ 需配置 |
| CNVD | 国家信息安全漏洞共享 | ❌ 需网络 |
| CNNVD | 国家信息安全漏洞库 | ❌ 需网络 |
| 中文厂商通告 | 奇安信/绿盟/深信服等 | ❌ 需网络 |

---

## 安装

### 环境要求
- Python 3.11+
- Windows / macOS / Linux

### 安装步骤

```bash
# 克隆项目
git clone https://github.com/h1kibi/Rcon-OSINT-Assistant.git
cd Rcon-OSINT-Assistant

# 安装依赖
pip install -e .

# 或手动安装
pip install PySide6 httpx sqlmodel pydantic pydantic-settings apscheduler loguru tomli tomli-w
```

### 配置

```bash
# 复制配置文件
cp config.example.toml config.toml

# 编辑配置（可选）
# 填入 API Key 以获得更好的数据源访问
```

**config.toml 关键配置：**

```toml
[nvd]
api_key = "你的NVD-API-Key"  # 可选，有Key速率更高

[github_advisory]
token = "你的GitHub-Token"   # 可选，有Token速率更高

[agent]
enabled = true
api_key = "你的AI-API-Key"   # AI 分析功能需要
model = "gpt-4o"
base_url = "https://api.openai.com/v1"
```

### 启动

```bash
python -m app.main
```

---

## 使用说明

### 基本操作

| 操作 | 方法 |
|------|------|
| 打开主面板 | 左键点击悬浮球 |
| 查看漏洞详情 | 双击表格中的漏洞行 |
| 搜索 | 顶部搜索框输入关键词或 CVE ID |
| 刷新数据 | 左侧栏 🔄 按钮 或 右键悬浮球 → 立即同步 |
| 设置 | 左侧栏 ⚙ 按钮 |
| 退出 | 右键悬浮球 → 退出程序 |

### AI 分析

1. 双击漏洞打开详情窗口
2. 点击「🤖 AI 分析」按钮
3. AI 自动联网搜索 + 分析漏洞
4. 分析完成后自动保存到 `data/analyses/{CVE_ID}/`
5. 可在「📁 分析记录」查看历史

### 搜索技巧

| 搜索词 | 结果 |
|--------|------|
| `CVE-2024-9999` | 精确匹配 CVE |
| `GHSA-xxxx` | 匹配 GitHub Advisory |
| `RCE` | 搜索标题和描述 |
| `WordPress` | 搜索产品名 |

---

## 评分体系

处置价值评分 (0-100)：

| 因素 | 权重 |
|------|------|
| CISA KEV 命中 | +35 |
| EPSS ≥ 0.95 | +20 |
| EPSS ≥ 0.85 | +12 |
| CVSS ≥ 9.0 | +20 |
| CVSS ≥ 7.0 | +12 |
| 24小时内发布 | +12 |
| 7天内发布 | +8 |
| 官方确认 | +10 |
| 官方补丁 | +8 |
| 公开 PoC | +10 |
| 多源确认 | +8 |
| 关注关键词 | +15 |

权重可在设置 → 评分配置中调整。

---

## 项目结构

```
Rcon-OSINT-Assistant/
├── app/
│   ├── main.py              # 入口
│   ├── config.py             # 配置
│   ├── logging_config.py     # 日志
│   ├── ui/
│   │   ├── floating_ball.py  # 悬浮球
│   │   ├── main_window.py    # 主窗口
│   │   ├── detail_window.py  # 详情窗口
│   │   ├── detail_panel.py   # 详情面板
│   │   ├── ai_analysis_window.py  # AI分析窗口
│   │   ├── agent_panel.py    # Agent对话面板
│   │   ├── settings_dialog.py # 设置
│   │   └── models.py         # 表格模型
│   ├── collectors/
│   │   ├── base.py           # 采集器接口
│   │   ├── nvd.py            # NVD
│   │   ├── cisa_kev.py       # CISA KEV
│   │   ├── epss.py           # EPSS
│   │   ├── github_advisory.py # GitHub Advisory
│   │   ├── osv.py            # OSV.dev
│   │   ├── cisa_rss.py       # CISA RSS
│   │   ├── msrc.py           # Microsoft MSRC
│   │   ├── cisco.py          # Cisco PSIRT
│   │   ├── redhat.py         # Red Hat
│   │   ├── ubuntu.py         # Ubuntu
│   │   ├── debian.py         # Debian
│   │   ├── cnvd.py           # CNVD
│   │   ├── cnnvd.py          # CNNVD
│   │   └── cn_vendor.py      # 中文厂商
│   ├── pipeline/
│   │   ├── scheduler.py      # 定时调度
│   │   ├── normalizer.py     # 标准化
│   │   ├── deduplicator.py   # 去重
│   │   ├── scorer.py         # 评分
│   │   ├── sync_service.py   # 同步服务
│   │   └── source_confidence.py # 来源可信度
│   ├── db/
│   │   ├── database.py       # 数据库
│   │   ├── models.py         # ORM模型
│   │   ├── repositories.py   # 数据仓库
│   │   └── migrations.py     # 迁移
│   └── utils/
│       ├── http.py           # HTTP客户端
│       ├── rate_limit.py     # 限流
│       ├── text.py           # 文本工具
│       ├── time.py           # 时间工具
│       └── analysis_storage.py # 分析存储
├── tests/                    # 测试
├── config.example.toml       # 配置示例
├── pyproject.toml            # 项目配置
├── README.md
└── .gitignore
```

---

## 技术栈

| 技术 | 用途 |
|------|------|
| Python 3.11+ | 主语言 |
| PySide6 | 桌面 GUI |
| SQLite + SQLModel | 数据存储 |
| APScheduler | 定时任务 |
| httpx | HTTP 请求 |
| pydantic-settings | 配置管理 |
| loguru | 日志 |

---

## 安全声明

本工具为**防御性漏洞情报工具**，仅用于：
- 收集公开漏洞情报
- 展示漏洞元数据
- 辅助安全团队进行漏洞优先级排序

本工具**不会**：
- 下载、执行或生成 PoC / Exploit 代码
- 自动验证漏洞
- 扫描互联网资产
- 绕过认证或进行攻击性测试

---

## 许可证

MIT License

---

## 致谢

- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities Catalog
- [FIRST EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [GitHub Advisory](https://github.com/advisories) - GitHub Security Advisories
- [OSV.dev](https://osv.dev/) - Open Source Vulnerabilities
