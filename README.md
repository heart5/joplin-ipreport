# joplin-ipreport

IP 监控分析报告生成模块（自 [happyjoplin](https://github.com/heart5/happyjoplin) 拆分，保留原 `etc/ipupdate.py` 的 Git 历史）。

## 功能

读取采集端的 IP 变化日志，检测网络/公网 IP 变化，补充归属地、实时网络与定位信息，生成图表并发布到 Joplin 笔记（「IP分析报告_<设备>」，ewmobile 笔记本）。无变化且 24 小时内已完整更新时跳过；缺定位时下一轮自动重试（GPSLogger 通知兜底、指数退避）。

## 目录

```
.
├── rootfile          # func.getdirmain() 仓库根标记
├── func/             # 公共库子模块（heart5/func）
├── etc/
│   ├── ipupdate.py   # 主程序
│   └── pathmagic.py  # sys.path 注入
├── tests/
│   └── ipupdate_logic_check.py
└── data/             # 机器本地配置（忽略）
```

## 运行

```bash
python etc/ipupdate.py
```

依赖：Python 3、matplotlib、pandas、requests；手机端可选 termux-api（`termux-location`、`termux-notification-list`）。Joplin 连接参数来自 `func` 的云端/本地配置。

## 部署

各主机克隆后：

```bash
git clone --recurse-submodules https://github.com/heart5/joplin-ipreport.git
mkdir -p data
cp <原 happyjoplin>/data/*.ini data/   # 机器本地状态与 Joplin 连接配置，不入库
```

`func` 子模块需与 happyjoplin 保持同一 commit，升级时两仓库同步。

cron wrapper（Termux 示例）：

```bash
cd ~/codebase/joplin-ipreport
timeout -s SIGTERM -k 2m 10m python etc/ipupdate.py
```

## 测试

```bash
python tests/ipupdate_logic_check.py
```
