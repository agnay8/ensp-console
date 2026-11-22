"""生成控制台用的示例 Excel：设备清单 + 命令表"""
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

OUT = Path(r"D:\huaweinet\console\samples")
OUT.mkdir(parents=True, exist_ok=True)

HEAD_FILL = PatternFill("solid", fgColor="EAF0FE")
HEAD_FONT = Font(bold=True, color="1D4ED8")

COMMANDS = {
    "R1": [
        "system-view",
        "sysname R1",
        "interface LoopBack0",
        " ip address 1.1.1.1 255.255.255.255",
        "interface GigabitEthernet0/0/0",
        " ip address 10.1.12.1 255.255.255.0",
        "interface GigabitEthernet0/0/1",
        " ip address 10.1.41.1 255.255.255.0",
        "quit",
        "ospf 1 router-id 1.1.1.1",
        " area 0",
        "  network 10.1.12.0 0.0.0.255",
        "  network 10.1.41.0 0.0.0.255",
        "  network 1.1.1.1 0.0.0.0",
    ],
    "R2": [
        "system-view",
        "sysname R2",
        "interface LoopBack0",
        " ip address 2.2.2.2 255.255.255.255",
        "interface GigabitEthernet0/0/0",
        " ip address 10.1.12.2 255.255.255.0",
        "interface GigabitEthernet0/0/1",
        " ip address 10.1.23.2 255.255.255.0",
        "quit",
        "ospf 1 router-id 2.2.2.2",
        " area 0",
        "  network 10.1.12.0 0.0.0.255",
        "  network 10.1.23.0 0.0.0.255",
        "  network 2.2.2.2 0.0.0.0",
    ],
    "R3": [
        "system-view",
        "sysname R3",
        "interface LoopBack0",
        " ip address 3.3.3.3 255.255.255.255",
        "interface GigabitEthernet0/0/0",
        " ip address 10.1.23.3 255.255.255.0",
        "interface GigabitEthernet0/0/1",
        " ip address 10.1.34.3 255.255.255.0",
        "quit",
        "ospf 1 router-id 3.3.3.3",
        " area 0",
        "  network 10.1.23.0 0.0.0.255",
        "  network 10.1.34.0 0.0.0.255",
        "  network 3.3.3.3 0.0.0.0",
    ],
    "R4": [
        "system-view",
        "sysname R4",
        "interface LoopBack0",
        " ip address 4.4.4.4 255.255.255.255",
        "interface GigabitEthernet0/0/0",
        " ip address 10.1.34.4 255.255.255.0",
        "interface GigabitEthernet0/0/1",
        " ip address 10.1.41.4 255.255.255.0",
        "quit",
        "ospf 1 router-id 4.4.4.4",
        " area 0",
        "  network 10.1.34.0 0.0.0.255",
        "  network 10.1.41.0 0.0.0.255",
        "  network 4.4.4.4 0.0.0.0",
    ],
}

ROLES = {
    "R1": ("AR2220", "核心（连接 R2 / R4）"),
    "R2": ("AR2220", "汇聚（连接 R1 / R3）"),
    "R3": ("AR2220", "汇聚（连接 R2 / R4）"),
    "R4": ("AR2220", "核心（连接 R3 / R1）"),
}


def head(ws, cols):
    ws.append(cols)
    for cell in ws[1]:
        cell.fill = HEAD_FILL
        cell.font = HEAD_FONT
        cell.alignment = Alignment(horizontal="center")
    ws.freeze_panes = "A2"


wb = Workbook()

ws1 = wb.active
ws1.title = "设备清单"
head(ws1, ["设备", "型号", "角色"])
for name, (model, role) in ROLES.items():
    ws1.append([name, model, role])
ws1.column_dimensions["A"].width = 12
ws1.column_dimensions["B"].width = 12
ws1.column_dimensions["C"].width = 26

ws2 = wb.create_sheet("OSPF命令")
head(ws2, ["设备", "命令"])
for name, cmds in COMMANDS.items():
    for c in cmds:
        ws2.append([name, c])
ws2.column_dimensions["A"].width = 12
ws2.column_dimensions["B"].width = 56

path = OUT / "设备与命令示例.xlsx"
wb.save(path)
print("saved", path, path.stat().st_size, "bytes")
