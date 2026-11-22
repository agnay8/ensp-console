"""巡检指标解析的样本测试（不连设备，只验证正则）"""

import sys

sys.path.insert(0, r"D:\huaweinet\console")

from patrol import (  # noqa: E402
    build_metrics,
    parse_cpu,
    parse_interfaces,
    parse_memory,
    parse_temperature,
    parse_transceiver,
    parse_version,
)

SAMPLES = {
    "cpu_ar": """CPU Usage Stat. Cycle: 60 (Second)
CPU Usage            : 5%  Max: 26%
CPU Usage Stat. Time : 2026-11-21  23:30:00

CPU utilization for five seconds: 5%: one minute: 5%: five minutes: 5%.""",
    "mem_table": """                                                 Total    Used    Free    Ratio
System Total Memory(KB)                        524288  157286  367002    30%""",
    "mem_text": "Memory Using Percentage Is: 42%",
    "transceiver": """GigabitEthernet0/0/1 transceiver diagnostic information:
  Current diagnostic parameters(dBM,mA,mV,Celsius):
    Temperature         : 33
    Voltage             : 3.28
    Bias Current        : 6.51
    RX Power            : -2.10
    TX Power            : -2.20
    Data Lane0 RX Power : -2.15""",
    "transceiver_table": """GigabitEthernet0/0/1 transceiver diagnostic information:
  Current diagnostic parameters:
    Temp.(C)  Voltage(V)  Bias(mA)  RX power(dBM)  TX power(dBM)
    35        3.29        6.50      -8.40          -2.10""",
    "ifbrief": """Interface                   PHY   Protocol InUti OutUti   inErrors  outErrors
GigabitEthernet0/0/0        up    up       0.01%  0.01%          0          0
GigabitEthernet0/0/1        up    up       0.01%  0.01%          0          0
GigabitEthernet0/0/2        down  down        0%     0%          0          0
Vlanif10                    up    up         --     --           0          0""",
    "version": """Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (AR2220 V200R005C20SPC200)
Copyright (C) 2012-2019 Huawei Technologies Co., Ltd.
HUAWEI AR2220 uptime is 0 week, 0 day, 1 hour, 20 minutes""",
    "temperature": """Temperature of the board:
  Temperature : 38""",
}

checks = []


def check(label, got, expect):
    ok = got == expect
    checks.append((ok, label, got, expect))


check("CPU 使用率", parse_cpu(SAMPLES["cpu_ar"]), 5)
check("内存（表格格式）", parse_memory(SAMPLES["mem_table"]), 30)
check("内存（文本格式）", parse_memory(SAMPLES["mem_text"]), 42)
check("温度", parse_temperature(SAMPLES["temperature"]), 38)

rx, tx = parse_transceiver(SAMPLES["transceiver"])
check("收光（key:value）", rx, -2.1)
check("发光（key:value）", tx, -2.2)

rx2, tx2 = parse_transceiver(SAMPLES["transceiver_table"])
check("收光（表格式）", rx2, -8.4)
check("发光（表格式）", tx2, -2.1)

up, down = parse_interfaces(SAMPLES["ifbrief"])
check("接口 UP", up, 3)
check("接口 DOWN", down, 1)

info = parse_version(SAMPLES["version"])
check("型号", info["model"], "AR2220 V200R005C20SPC200")
check("版本", info["version"], "5.170")
check("运行时长", info["uptime"], "0 week, 0 day, 1 hour, 20 minutes")

# 完整指标集
raw = [
    {"command": "display version", "output": SAMPLES["version"]},
    {"command": "display cpu-usage", "output": SAMPLES["cpu_ar"]},
    {"command": "display memory-usage", "output": SAMPLES["mem_table"]},
    {"command": "display interface brief", "output": SAMPLES["ifbrief"]},
    {"command": "display transceiver diagnosis interface", "output": SAMPLES["transceiver"]},
    {"command": "display temperature all", "output": SAMPLES["temperature"]},
]
metrics = build_metrics(raw)
by_key = {m["key"]: m for m in metrics}

check("指标数量", len(metrics), 10)
check("CPU 等级正常", by_key["cpu"]["level"], "ok")
check("收光等级正常", by_key["rx_power"]["level"], "ok")
check("DOWN 接口告警", by_key["if_down"]["level"], "warn")
check("型号文本", by_key["model"]["value"], "AR2220 V200R005C20SPC200")

# 弱光场景
weak = build_metrics(
    [{"command": "display transceiver diagnosis interface", "output": SAMPLES["transceiver"].replace("-2.10", "-26.30")}]
)
weak_rx = {m["key"]: m for m in weak}["rx_power"]
check("弱光判异常", weak_rx["level"], "crit")

print(f"{'结果':<6}{'检查项':<22}{'实际':<32}期望")
print("-" * 88)
for ok, label, got, expect in checks:
    print(f"{'PASS' if ok else 'FAIL':<6}{label:<22}{str(got):<32}{expect}")

failed = [c for c in checks if not c[0]]
print("-" * 88)
print(f"总计 {len(checks)} 项，通过 {len(checks) - len(failed)}，失败 {len(failed)}")
sys.exit(1 if failed else 0)
