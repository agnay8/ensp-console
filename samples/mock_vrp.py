"""模拟 5 台 VRP 设备的 console（telnet），用于巡检功能端到端测试。

监听 127.0.0.1:2000-2004，各自返回不同的 CPU / 内存 / 温度 / 光功率，
其中 LSW2 故意超阈值、LSW3 没有光模块，用来验证告警与缺失指标。
"""

import asyncio

import telnetlib3

PROFILES = {
    2000: dict(host="R1", model="AR2220 V200R005C20SPC200", cpu=5, mem=30, temp=38,
               rx="-2.10", tx="-2.20", ifs=[("GigabitEthernet0/0/0", "up"), ("GigabitEthernet0/0/1", "up"), ("GigabitEthernet0/0/2", "down")]),
    2001: dict(host="LSW1", model="S5700 V200R005C00SPC500", cpu=12, mem=42, temp=41,
               rx="-8.40", tx="-2.10", ifs=[("GigabitEthernet0/0/1", "up"), ("GigabitEthernet0/0/2", "up"), ("GigabitEthernet0/0/10", "up"), ("GigabitEthernet0/0/11", "up")]),
    2002: dict(host="LSW2", model="S5700 V200R005C00SPC500", cpu=78, mem=81, temp=63,
               rx="-26.30", tx="-2.40", ifs=[("GigabitEthernet0/0/1", "up"), ("GigabitEthernet0/0/2", "up"), ("GigabitEthernet0/0/10", "down")]),
    2003: dict(host="LSW3", model="S5700 V200R005C00SPC500", cpu=8, mem=35, temp=39,
               rx=None, tx=None, ifs=[("GigabitEthernet0/0/1", "up"), ("GigabitEthernet0/0/2", "up")]),
    2004: dict(host="LSW4", model="S5700 V200R005C00SPC500", cpu=15, mem=48, temp=44,
               rx="-3.20", tx="-2.80", ifs=[("GigabitEthernet0/0/1", "up"), ("GigabitEthernet0/0/20", "up")]),
}


def version_text(p):
    return (
        "Huawei Versatile Routing Platform Software\r\n"
        f"VRP (R) software, Version 5.170 ({p['model']})\r\n"
        "Copyright (C) 2012-2019 Huawei Technologies Co., Ltd.\r\n"
        f"HUAWEI {p['host']} uptime is 0 week, 2 day, 3 hour, 20 minutes"
    )


def cpu_text(p):
    return (
        "CPU Usage Stat. Cycle: 60 (Second)\r\n"
        f"CPU Usage            : {p['cpu']}%  Max: 89%\r\n"
        "CPU Usage Stat. Time : 2026-11-21  23:40:00\r\n\r\n"
        f"CPU utilization for five seconds: {p['cpu']}%: one minute: {p['cpu']}%: five minutes: {p['cpu']}%."
    )


def memory_text(p):
    used = int(524288 * p["mem"] / 100)
    return (
        "                                                 Total    Used    Free    Ratio\r\n"
        f"System Total Memory(KB)                        524288  {used}  {524288 - used}    {p['mem']}%"
    )


def interface_text(p):
    lines = ["Interface                   PHY   Protocol InUti OutUti   inErrors  outErrors"]
    for name, state in p["ifs"]:
        lines.append(f"{name:<28}{state:<6}{state:<9}0.01%  0.01%          0          0")
    return "\r\n".join(lines)


def transceiver_text(p):
    if p["rx"] is None:
        return "Error: The port does not support transceiver diagnosis."
    return (
        "GigabitEthernet0/0/1 transceiver diagnostic information:\r\n"
        "  Current diagnostic parameters(dBM,mA,mV,Celsius):\r\n"
        f"    Temperature         : {p['temp']}\r\n"
        "    Voltage             : 3.28\r\n"
        "    Bias Current        : 6.51\r\n"
        f"    RX Power            : {p['rx']}\r\n"
        f"    TX Power            : {p['tx']}"
    )


def temperature_text(p):
    return f"Temperature of the board:\r\n  Temperature : {p['temp']}"


def config_text(p):
    host = p["host"]
    lines = [
        "#",
        f"sysname {host}",
        "#",
        "interface GigabitEthernet0/0/1",
        f" ip address 10.0.{p['port'] % 100}.2 255.255.255.0",
        "#",
    ]
    if host.startswith("LSW"):
        lines += [
            "vlan batch 10 20 30",
            "interface Vlanif10",
            " ip address 192.168.10.252 255.255.255.0",
            " vrrp vrid 10 virtual-ip 192.168.10.254",
            "#",
        ]
    else:
        lines += [
            "interface GigabitEthernet0/0/0",
            " ip address 10.0.1.1 255.255.255.0",
            "#",
        ]
    lines += [
        "ospf 1 router-id 1.1.1.1",
        " area 0.0.0.0",
        "  network 10.0.0.0 0.0.0.255",
        "#",
        "return",
    ]
    return "\r\n".join(lines)


def respond(p, cmd: str) -> str:
    c = cmd.lower().strip()
    if c.startswith("display version"):
        return version_text(p)
    if c.startswith("display cpu-usage"):
        return cpu_text(p)
    if c.startswith("display memory-usage"):
        return memory_text(p)
    if c.startswith("display interface brief"):
        return interface_text(p)
    if c.startswith("display transceiver"):
        return transceiver_text(p)
    if c.startswith("display temperature"):
        return temperature_text(p)
    if c.startswith("display current-configuration"):
        return config_text(p)
    if c.startswith("screen-length"):
        return ""
    if c.startswith("ping"):
        target = c.split()[-1]
        return (
            f"  PING {target}: 56 data bytes, press CTRL_C to break\r\n"
            f"    Reply from {target}: bytes=56 Sequence=1 ttl=254 time=1 ms\r\n"
            f"  --- {target} ping statistics ---\r\n"
            "    1 packet(s) transmitted\r\n"
            "    1 packet(s) received\r\n"
            "    0.00% packet loss"
        )
    return "Error: Unrecognized command found at '^' position."


def make_shell(port: int):
    profile = PROFILES[port]
    profile.setdefault("port", port)
    prompt = f"<{profile['host']}>"

    async def shell(reader, writer):
        writer.write(f"\r\n{prompt}\r\n")
        await writer.drain()
        while True:
            try:
                line = await reader.readline()
            except Exception:
                break
            if not line:
                break
            cmd = line.strip()
            if not cmd:
                writer.write(f"{prompt}\r\n")
                await writer.drain()
                continue
            body = respond(profile, cmd)
            writer.write(f"{body}\r\n{prompt}\r\n" if body else f"{prompt}\r\n")
            await writer.drain()

    return shell


async def main():
    servers = []
    for port in PROFILES:
        server = await telnetlib3.create_server(
            host="127.0.0.1", port=port, shell=make_shell(port), encoding="utf8"
        )
        servers.append(server)
    print("mock VRP listening:", ", ".join(str(p) for p in PROFILES), flush=True)
    await asyncio.gather(*(s.wait_closed() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
