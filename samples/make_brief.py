from pathlib import Path

from docx import Document
from docx.shared import Pt

OUT = Path(r"D:\huaweinet\console\samples")
OUT.mkdir(parents=True, exist_ok=True)

doc = Document()
style = doc.styles["Normal"]
style.font.name = "微软雅黑"
style.font.size = Pt(10.5)

doc.add_heading("实验四  OSPF 单区域路由配置", level=1)

doc.add_heading("一、实验目的", level=2)
doc.add_paragraph("掌握 OSPF 单区域的基本配置方法，理解邻居建立过程与路由计算。")

doc.add_heading("二、实验拓扑", level=2)
doc.add_paragraph("使用四台 AR2220 路由器组成环形网络，设备命名为 R1、R2、R3、R4，依次环形互联。")
doc.add_paragraph("互联链路地址规划如下：")
t = doc.add_table(rows=1, cols=3)
t.style = "Table Grid"
hdr = t.rows[0].cells
hdr[0].text, hdr[1].text, hdr[2].text = "链路", "网段", "说明"
for row in [
    ("R1 - R2", "10.1.12.0/24", "R1 取 .1，R2 取 .2"),
    ("R2 - R3", "10.1.23.0/24", "R2 取 .2，R3 取 .3"),
    ("R3 - R4", "10.1.34.0/24", "R3 取 .3，R4 取 .4"),
    ("R4 - R1", "10.1.41.0/24", "R4 取 .4，R1 取 .1"),
]:
    cells = t.add_row().cells
    cells[0].text, cells[1].text, cells[2].text = row

doc.add_paragraph("每台路由器配置 Loopback0 作为 Router-ID：R1 为 1.1.1.1/32，R2 为 2.2.2.2/32，R3 为 3.3.3.3/32，R4 为 4.4.4.4/32。")

doc.add_heading("三、配置要求", level=2)
doc.add_paragraph("1. 四台路由器均运行 OSPF 进程 1，全部划入区域 0。", style="List Number")
doc.add_paragraph("2. Router-ID 使用各自的 Loopback0 地址。", style="List Number")
doc.add_paragraph("3. 互联网段与 Loopback 网段全部通过 network 命令宣告。", style="List Number")
doc.add_paragraph("4. 配置完成后保存配置。", style="List Number")

doc.add_heading("四、验证要求", level=2)
doc.add_paragraph("display ospf peer brief 应看到邻居状态为 Full；任意两台路由器的 Loopback 地址应能互通。")

path = OUT / "实验四-OSPF单区域任务书.docx"
doc.save(path)
print("saved", path, path.stat().st_size, "bytes")

# 同内容纯文本版，方便快速验证
txt = OUT / "实验四-OSPF单区域任务书.txt"
txt.write_text(
    """实验四 OSPF 单区域路由配置

一、实验目的
掌握 OSPF 单区域的基本配置方法。

二、实验拓扑
四台 AR2220 路由器 R1、R2、R3、R4 环形互联。
R1 - R2  10.1.12.0/24
R2 - R3  10.1.23.0/24
R3 - R4  10.1.34.0/24
R4 - R1  10.1.41.0/24
Loopback0：1.1.1.1/32、2.2.2.2/32、3.3.3.3/32、4.4.4.4/32

三、配置要求
1. 四台路由器运行 OSPF 进程 1，划入区域 0。
2. Router-ID 使用 Loopback0 地址。
3. 全部网段通过 network 宣告。

四、验证要求
display ospf peer brief 邻居应为 Full。
""",
    encoding="utf-8",
)
print("saved", txt, txt.stat().st_size, "bytes")
