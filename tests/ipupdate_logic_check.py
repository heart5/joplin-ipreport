#!/usr/bin/env python3
# 一次性：报告端 detect_ip_changes「未知不计变化 / 未知不覆盖已知」逻辑验证
# monkeypatch getcfpoptionvalue/setcfpoptionvalue 为内存字典，不触碰真实 ini
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.chdir(REPO)
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "etc"))

spec = importlib.util.spec_from_file_location("ipupdate", REPO / "etc" / "ipupdate.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

STORE = {}


def fake_get(_cfg, section, key, *_a, **_k):
    return STORE.get(f"{section}.{key}")


def fake_set(_cfg, section, key, value, *_a, **_k):
    STORE[f"{section}.{key}"] = value


m.getcfpoptionvalue = fake_get
m.setcfpoptionvalue = fake_set

SEC = m.IP_UPDATE_CONFIG_SECTION
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS: {name}")
    else:
        FAIL += 1
        print(f"FAIL: {name}")


def rec(
    wifi,
    pub="1.1.1.1",
    net="WiFi",
    lip="192.168.1.5",
    vi="N/A",
    vip="N/A",
    cn="1.1.1.1",
    src="ipsb",
    bssid="aa:bb:cc:dd:ee:01",
):
    return {
        "timestamp": "2026-10-11 12:00:00",
        "network": net,
        "wifi_name": wifi,
        "public_ip": pub,
        "local_ip": lip,
        "vpn_interface": vi,
        "vpn_ip": vip,
        "public_ip_source": src,
        "public_ip_cn": cn,
        "wifi_bssid": bssid,
    }


def seed(last):
    STORE.clear()
    if last is not None:
        STORE[f"{SEC}.last_record"] = json.dumps(last, ensure_ascii=False)


def stored():
    return json.loads(STORE.get(f"{SEC}.last_record") or "null")


def stored_raw():
    return STORE.get(f"{SEC}.last_record")


# 0. 归一 helper 直测
check("helper NaN→None", m._sanitize_field_value(float("nan")) is None)
check("helper None→None", m._sanitize_field_value(None) is None)
check("helper pd.NA→None", m._sanitize_field_value(m.pd.NA) is None)
check("helper 有效值strip", m._sanitize_field_value(" tun0 ") == "tun0")
check("helper N/A保留", m._sanitize_field_value("N/A") == "N/A")
check("helper public Unknown→None", m._normalize_unknown("Unknown", m.BLANK_VALUES) is None)

# 1. 首跑：last_record 空 → True + 写入当前记录（NaN 写为 null）
seed(None)
ok, ch = m.detect_ip_changes(rec("HomeNet"))
check("首跑 返回True(initial)", ok and ch.get("initial"))
check("首跑 写入基线", stored() == rec("HomeNet"))

seed(None)
ok, ch = m.detect_ip_changes(rec("HomeNet", pub=float("nan")))
check("首跑含NaN 写null无NaN", stored()["public_ip"] is None and "NaN" not in (stored_raw() or ""))

# 2. 已知→未知（其余字段同）→ False 不计变化，不写 ini
seed(rec("HomeNet"))
ok, ch = m.detect_ip_changes(rec(None))
check("已知→未知 无变化", (not ok) and ch == {})
check("已知→未知 基线保留", stored()["wifi_name"] == "HomeNet")

# 3. 已知→未知 + 公网变 → True 且仅记公网；写基线时 WiFi 保留最近已知
seed(rec("HomeNet"))
ok, ch = m.detect_ip_changes(rec(None, pub="2.2.2.2"))
check("混合变化 返回True", ok)
check("混合变化 仅公网", set(ch.keys()) == {"public_ip"})
check("混合变化 基线保留已知wifi", stored()["wifi_name"] == "HomeNet")
check("混合变化 基线公网更新", stored()["public_ip"] == "2.2.2.2")

# 4. 未知→已知 → True（首次学习真名）
seed(rec(None))
ok, ch = m.detect_ip_changes(rec("HomeNet"))
check("未知→已知 返回True", ok and "wifi_name" in ch)

# 5. 已知→已知不同 → True（换网正常记录）
seed(rec("HomeNet"))
ok, ch = m.detect_ip_changes(rec("OfficeNet"))
check("已知→已知不同 返回True", ok and ch["wifi_name"] == {"old": "HomeNet", "new": "OfficeNet"})

# 6. 已知→已知相同 → False
seed(rec("HomeNet"))
ok, ch = m.detect_ip_changes(rec("HomeNet"))
check("已知→已知相同 无变化", (not ok) and ch == {})

# 7. NaN 场景：NaN→NaN、已知→NaN、NaN→已知
seed(rec("HomeNet", pub=float("nan")))
before = stored_raw()
ok, ch = m.detect_ip_changes(rec("HomeNet", pub=float("nan")))
check("NaN→NaN 无变化", (not ok) and ch == {})
check("NaN→NaN 不写ini", stored_raw() == before)

seed(rec("HomeNet", pub="1.1.1.1"))
ok, ch = m.detect_ip_changes(rec("HomeNet", pub=float("nan")))
check("已知→NaN 无变化", (not ok) and ch == {})
check("已知→NaN 基线保留", stored()["public_ip"] == "1.1.1.1")

seed(rec("HomeNet", pub=float("nan")))
ok, ch = m.detect_ip_changes(rec("HomeNet", pub="2.2.2.2"))
check("NaN→已知 记变化", ok and ch["public_ip"] == {"old": None, "new": "2.2.2.2"})
check("NaN→已知 状态净化", stored()["public_ip"] == "2.2.2.2" and "NaN" not in (stored_raw() or ""))

# 8. 混合：公网 NaN + WiFi 未知 + network 真变 → 仅 network；已知基线保留
seed(rec("HomeNet", pub="1.1.1.1"))
ok, ch = m.detect_ip_changes(rec(None, pub=float("nan"), net="Mobile"))
check("混合NaN 仅network", ok and set(ch.keys()) == {"network"})
check("混合NaN 保留公网", stored()["public_ip"] == "1.1.1.1")
check("混合NaN 保留wifi", stored()["wifi_name"] == "HomeNet")
check("混合NaN 存储无NaN", "NaN" not in (stored_raw() or ""))

# 9. VPN 的 N/A 是真实状态：tun0 ↔ N/A 两个方向都要记变化
seed(rec("HomeNet", vi="tun0", vip="172.19.0.1"))
ok, ch = m.detect_ip_changes(rec("HomeNet", vi="N/A", vip="N/A"))
check("VPN断开 记变化", ok and ch["vpn_interface"] == {"old": "tun0", "new": "N/A"})
check("VPN断开 写N/A", stored()["vpn_interface"] == "N/A" and stored()["vpn_ip"] == "N/A")

seed(rec("HomeNet", vi="N/A", vip="N/A"))
ok, ch = m.detect_ip_changes(rec("HomeNet", vi="tun0", vip="172.19.0.1"))
check("VPN连接 记变化", ok and ch["vpn_interface"] == {"old": "N/A", "new": "tun0"})

# 10. 报告统计：两端都有有效观测才计变化
df = m.pd.DataFrame(
    {
        "timestamp": m.pd.date_range(end=m.pd.Timestamp.now(), periods=5, freq="min"),
        "network": ["WiFi"] * 5,
        "wifi_name": ["HomeNet"] * 5,
        "public_ip": [None, "1.1.1.1", None, "1.1.1.1", "2.2.2.2"],
        "local_ip": ["192.168.1.5"] * 5,
        "vpn_interface": ["N/A"] * 5,
        "vpn_ip": ["N/A"] * 5,
    }
)
analysis = m.analyze_ip_data(df, days=1)
check("统计 变化次数=1", analysis["summary"]["public_ip_changes"] == 1)

# 11. 解析器：旧 7 字段 / 新 9 字段 / 未知键忽略 / 畸形行跳过 / 哨兵归一
import tempfile


def parse_lines(lines):
    fd, name = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    p = Path(name)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        return m.parse_ip_log_file(p)
    finally:
        p.unlink()


old_line = (
    "2026-10-01 10:00:00 | Network: WiFi | WiFi_Name: HomeNet | Public_IP: 1.1.1.1 | "
    "Local_IP: 192.168.1.5 | VPN_Interface: N/A | VPN_IP: N/A"
)
new_line = old_line + " | Public_IP_Source: hcx-echo | Public_IP_CN: 2.2.2.2 | WiFi_BSSID: AA:BB:CC:DD:EE:01"
unknown_line = old_line + " | Public_IP_Source: unknown | Public_IP_CN: Unknown | WiFi_BSSID: Unknown"
bad_line = "2026-10-01 10:05:00 | Network: WiFi | WiFi_Name: X"
pdf = parse_lines([old_line, new_line + " | Extra_Future_Key: xx", unknown_line, bad_line, "garbage"])
check("解析 有效行数3", len(pdf) == 3)
check("解析 旧行新字段为空", m.pd.isna(pdf.iloc[0]["public_ip_cn"]) and m.pd.isna(pdf.iloc[0]["public_ip_source"]))
check("解析 新行source/cn", pdf.iloc[1]["public_ip_source"] == "hcx-echo" and pdf.iloc[1]["public_ip_cn"] == "2.2.2.2")
check("解析 BSSID保留原值", pdf.iloc[1]["wifi_bssid"] == "AA:BB:CC:DD:EE:01")
check("解析 哨兵归一", pdf.iloc[0]["public_ip"] == "1.1.1.1")
p2 = parse_lines([unknown_line])
check(
    "解析 未知归一None",
    p2.iloc[0]["public_ip_cn"] is None and p2.iloc[0]["public_ip_source"] is None,
)
check("解析 旧行无Source标记", not pdf.iloc[0]["source_recorded"])
check("解析 未知Source有标记", p2.iloc[0]["source_recorded"])

# 12. 国内公网IP变化检测
seed(rec("HomeNet"))
ok, ch = m.detect_ip_changes(rec("HomeNet", cn=None))
check("CN已知→未知 无变化", (not ok) and ch == {})

seed(rec("HomeNet", cn=None))
ok, ch = m.detect_ip_changes(rec("HomeNet", cn="3.3.3.3"))
check("CN未知→已知 记变化", ok and ch["public_ip_cn"] == {"old": None, "new": "3.3.3.3"})

seed(rec("HomeNet", cn="3.3.3.3"))
ok, ch = m.detect_ip_changes(rec("HomeNet", cn="4.4.4.4"))
check("CN已知→已知不同 记变化", ok and ch["public_ip_cn"] == {"old": "3.3.3.3", "new": "4.4.4.4"})

seed(rec("HomeNet", src="ipsb", bssid="aa:bb:cc:dd:ee:01"))
ok, ch = m.detect_ip_changes(rec("HomeNet", src="hcx-echo", bssid="aa:bb:cc:dd:ee:02"))
check("仅Source/BSSID变化 不触发", (not ok) and ch == {})
check("仅Source/BSSID变化 不写ini", stored()["public_ip_source"] == "ipsb")

seed(rec("HomeNet", src="ipsb"))
ok, ch = m.detect_ip_changes(rec("OfficeNet", src="unknown"))
check("Source未知不覆盖已知", ok and stored()["public_ip_source"] == "ipsb")

# 13. 分析：CN 切换 / 来源分布 / AP 统计 / latest_record
df2 = m.pd.DataFrame(
    {
        "timestamp": m.pd.date_range(end=m.pd.Timestamp.now(), periods=5, freq="min"),
        "network": ["WiFi"] * 5,
        "wifi_name": ["HomeNet"] * 5,
        "public_ip": ["1.1.1.1", "1.1.1.1", "2.2.2.2", "2.2.2.2", "2.2.2.2"],
        "local_ip": ["192.168.1.5"] * 5,
        "vpn_interface": ["N/A"] * 5,
        "vpn_ip": ["N/A"] * 5,
        "public_ip_source": ["ipsb", "ipsb", "hcx-echo", None, "ipsb"],
        "public_ip_cn": ["9.9.9.9", "9.9.9.9", "9.9.9.8", "9.9.9.8", "9.9.9.8"],
        "wifi_bssid": [
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "Unknown",
            "aa:bb:cc:dd:ee:02",
        ],
    }
)
a2 = m.analyze_ip_data(df2, days=1)
check("分析 国际切换=1", a2["summary"]["public_ip_changes"] == 1)
check("分析 国内切换=1", a2["summary"]["public_ip_cn_changes"] == 1)
check(
    "分析 来源分布",
    a2["summary"]["source_stats"] == {"ipsb": 3, "hcx-echo": 1, "未记录": 1},
)
ws = a2["summary"]["wifi_stats"]["HomeNet"]
check("分析 AP计数", ws["bssid_count"] == 2)
check("分析 最近AP", ws["latest_bssid"] == "aa:bb:cc:dd:ee:02")
check("分析 latest含CN", a2["latest_record"]["public_ip_cn"] == "9.9.9.8")
check("分析 recent_log含cn_changed", sum(1 for e in a2["detail"]["recent_log"] if e["cn_changed"]) == 1)

# 14. 渲染冒烟：国内出口行 / 端点来源 / AP / 动态国内IP列
cfg = m.IpConfig(device_id="matex2", host_user="MateX2", log_file=Path("/tmp/ip.log"), report_days=7)
geo = {
    "1.1.1.1": {"place": "深圳 电信", "isp": "电信"},
    "2.2.2.2": {"place": "香港", "isp": "PCCW"},
    "9.9.9.9": {"place": "北京", "isp": "联通"},
    "9.9.9.8": {"place": "广州", "isp": "移动"},
}
report = m.render_report(a2, cfg, None, geo)
check("渲染 国内出口行", "🇨🇳 **国内出口**" in report)
check("渲染 端点来源", "🔌 **端点来源**" in report)
check("渲染 AP显示", "AP aa:bb:cc:dd:ee:02" in report)
check("渲染 国内IP列", "| 时间 | 公网IP | 国内IP | 网络 |" in report)
check("渲染 国际切换文案", "国际IP切换" in report)
check("渲染 来源标签", "HCX 自建 1" in report)

df3 = df2.copy()
df3["public_ip_cn"] = df3["public_ip"]
a3 = m.analyze_ip_data(df3, days=1)
r3 = m.render_report(a3, cfg, None, geo)
check("渲染 同出口注记", "国内同出口" in r3)
check("渲染 无CN差异不加列", "| 时间 | 公网IP | 国内IP | 网络 |" not in r3)

# 15. 表格空值改为显式文案；脚注空行分隔，不再并入表格
n = 18
df4 = m.pd.DataFrame(
    {
        "timestamp": m.pd.date_range(end=m.pd.Timestamp.now(), periods=n, freq="min"),
        "network": ["Mobile"] * n,
        "wifi_name": ["Unknown_WiFi"] * n,
        "public_ip": ["1.1.1.1"] * (n - 2) + ["1.1.1.1", None],
        "local_ip": ["N/A"] * n,
        "vpn_interface": ["tun0"] * n,
        "vpn_ip": ["172.19.0.1"] * n,
        "public_ip_source": ["ipsb"] * (n - 2) + ["ipsb", "unknown"],
        "source_recorded": [True] * n,
        "public_ip_cn": ["9.9.9.9"] * (n - 2) + ["9.9.9.9", None],
        "wifi_bssid": ["N/A"] * n,
    }
)
a4 = m.analyze_ip_data(df4, days=1)
r4 = m.render_report(a4, cfg, None, geo)
check("渲染 IP探测失败文案", "⚠️ 探测失败" in r4)
check("渲染 CN探测失败文案", "| 探测失败 |" in r4)
check("渲染 脚注独立成段", "| Mobile |\n\n*（共 18 条，仅列最近 15 条）*" in r4)

df5 = df4.drop(columns=["public_ip_source", "source_recorded"]).copy()
df5.loc[16, "public_ip"] = None
df5.loc[16, "public_ip_cn"] = None
a5 = m.analyze_ip_data(df5, days=1)
r5 = m.render_report(a5, cfg, None, geo)
check("渲染 旧格式未记录文案", "| 未记录 | 未记录 |" in r5)

# 16. GPSLogger 通知解析与采集（兜底一）
NOW = m.datetime(2026, 10, 25, 9, 30, 0)


def close(a, b, tol=1e-5):
    return a is not None and b is not None and abs(a - b) <= tol


lat, lng = m._parse_gpslogger_coords('26° 35\' 16.1952" N, 106° 42\' 47.5524" E')
check("通知坐标 DMS N/E", close(lat, 26.587832) and close(lng, 106.713209))
lat, lng = m._parse_gpslogger_coords('26° 35\' 16.1952" S, 106° 42\' 47.5524" W')
check("通知坐标 DMS S/W", close(lat, -26.587832) and close(lng, -106.713209))
lat, lng = m._parse_gpslogger_coords("26° 35' N, 106° 42' E")
check("通知坐标 DMS 可选秒", close(lat, 26.583333) and close(lng, 106.7))
lat, lng = m._parse_gpslogger_coords("26.5878, 106.7130")
check("通知坐标 十进制对", close(lat, 26.5878) and close(lng, 106.713))
lat, lng = m._parse_gpslogger_coords("26.5878° N, 106.7130° E")
check("通知坐标 十进制半球", close(lat, 26.5878) and close(lng, 106.713))
check("通知坐标 状态文本拒绝", m._parse_gpslogger_coords("GPSLogger is still running.") is None)
check("通知坐标 越界拒绝", m._parse_gpslogger_coords('26° 35\' 16" N, 200° 42\' 47" E') is None)
check("通知坐标 0,0拒绝", m._parse_gpslogger_coords("0, 0") is None)
check("通知坐标 畸形DMS不误拆", m._parse_gpslogger_coords('26° 60\' 16.1952" N, 106° 42\' 47.5524" E') is None)
check("通知时间 有效", m._parse_gpslogger_time("2026-10-25 09:29:08") == m.datetime(2026, 10, 25, 9, 29, 8))
check("通知时间 无效", m._parse_gpslogger_time(None) is None)


def notif(title, when, content="Altitude: 0 meters Duration: 3m Accuracy: 30\xa0meters"):
    return {"packageName": m.GPSLOGGER_PACKAGE, "title": title, "when": when, "content": content}


items_multi = [
    notif("26° 35' 16.1952\" N, 106° 42' 47.5524\" E", "2026-10-25 09:20:00"),
    notif("26° 35' 20.0000\" N, 106° 42' 50.0000\" E", "2026-10-25 09:28:00"),
]
orig_termux = m._run_termux_json
m._run_termux_json = lambda args, timeout: items_multi
loc = m.collect_gpslogger_location(now=NOW)
check("通知采集 选择最新", loc and close(loc["latitude"], 26.588889, 1e-4) and loc["provider"] == "gpslogger")
check("通知采集 NBSP精度", loc and loc["accuracy"] == 30.0)
m._run_termux_json = lambda args, timeout: [notif(items_multi[0]["title"], "2026-10-25 08:00:00")]
check("通知采集 过期拒绝", m.collect_gpslogger_location(now=NOW) is None)
m._run_termux_json = lambda args, timeout: [notif(items_multi[0]["title"], "2026-10-25 10:00:00")]
check("通知采集 未来拒绝", m.collect_gpslogger_location(now=NOW) is None)
m._run_termux_json = lambda args, timeout: [notif(items_multi[0]["title"], None)]
check("通知采集 无时间拒绝", m.collect_gpslogger_location(now=NOW) is None)
m._run_termux_json = lambda args, timeout: {"not": "list"}
check("通知采集 非列表拒绝", m.collect_gpslogger_location(now=NOW) is None)
m._run_termux_json = orig_termux

# 17. collect_live_location 回退链顺序
calls = []


def fake_termux(responses):
    def _fake(args, timeout):
        calls.append(tuple(args))
        if "once" in args:
            return responses.get("once")
        if "last" in args:
            return responses.get("last")
        return responses.get("notif")

    return _fake


once_ok = {"latitude": 1.0, "longitude": 2.0, "provider": "network", "accuracy": 10}
last_ok = {"latitude": 3.0, "longitude": 4.0, "accuracy": 20}
m._run_termux_json = fake_termux({"once": once_ok} | {"notif": items_multi})
calls.clear()
loc = m.collect_live_location(now=NOW)
check("定位链 once成功", loc and loc["provider"] == "network" and loc["latitude"] == 1.0)
check("定位链 once成功不读通知", all("termux-location" in c for c in calls) and len(calls) == 1)

m._run_termux_json = fake_termux({"notif": items_multi, "last": last_ok})
calls.clear()
loc = m.collect_live_location(now=NOW)
check("定位链 once失败→通知", loc and loc["provider"] == "gpslogger")
check("定位链 通知成功不调last", not any("last" in c for c in calls))

m._run_termux_json = fake_termux({"notif": [], "last": last_ok})
loc = m.collect_live_location(now=NOW)
check("定位链 通知失败→last", loc and loc["provider"] == "cached" and loc["latitude"] == 3.0)

m._run_termux_json = fake_termux({})
check("定位链 全失败None", m.collect_live_location(now=NOW) is None)

calls.clear()
m._run_termux_json = fake_termux({"notif": items_multi, "last": last_ok})
loc = m.collect_live_location(retry=True, now=NOW)
check("重试链 跳过once", not any("once" in c for c in calls))
check("重试链 通知优先", loc and loc["provider"] == "gpslogger")
m._run_termux_json = orig_termux

# 18. 缺定位重试状态机
check("重试 _ini_truthy int1", m._ini_truthy(1) is True)
check("重试 _ini_truthy str0", m._ini_truthy("0") is False)
check("重试 _ini_truthy None", m._ini_truthy(None) is False)
check("重试 退避0", m._location_retry_delay(0) == 0 and m._location_retry_delay(9) == 0)
check("重试 退避10=360", m._location_retry_delay(10) == 360)
check("重试 退避11=720", m._location_retry_delay(11) == 720)
check("重试 退避封顶", m._location_retry_delay(14) == 3600 and m._location_retry_delay(99) == 3600)

STORE.clear()
m._write_location_state(True, 2)
check("重试 状态写入", STORE[f"{SEC}.location_missing"] == "1" and STORE[f"{SEC}.location_retry_failures"] == "2")
check("重试 状态读取", m._get_int_option("location_retry_failures") == 2 and m._ini_truthy(STORE[f"{SEC}.location_missing"]))
m._write_location_state(False, 0)
check("重试 状态复位", STORE[f"{SEC}.location_missing"] == "0" and m._get_int_option("location_retry_failures") == 0)

orig_which = m.shutil.which
m.shutil.which = lambda name: None
check("重试 非Termux不重试", m._location_capable() is False)
m.shutil.which = orig_which
check("重试 Termux可重试", m._location_capable() is True)

print("-" * 40)
print(f"PASS={PASS} FAIL={FAIL}")
sys.exit(0 if FAIL == 0 else 1)
