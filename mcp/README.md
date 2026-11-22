# eNSP MCP 服务端源码（v1.3.0）

本目录是控制台依赖的 MCP 服务端 `ensp-mcp` 的完整源码快照。控制台的拓扑解析、命令下发、在线探测等能力都直接调用它，不重造解析逻辑。

> 说明：这是从本机 `C:\Users\agnay\.venvs\ensp-mcp\Lib\site-packages\ensp_mcp\`（wheel 安装，版本 1.3.0）快照而来，仅作存档与查阅；运行时仍以 venv 里安装的包为准。修改本目录不会影响已安装的服务端。

## 模块速览

| 文件 | 职责 |
|---|---|
| `server.py` | MCP 入口与全部工具实现（topo_inspect / device_batch / environment_check 等） |
| `topo.py` | eNSP `.topo` 文件解析（设备 / 接口 / 链路 / system_mac） |
| `console.py` | 设备 console 连接池（Telnet 提示符识别、分页、确认符处理） |
| `commandlog.py` | 命令下发流水（控制台「执行记录」的数据源） |
| `preflight.py` / `doctor.py` | eNSP / VirtualBox / 虚拟化 / Host-Only 环境预检 |
| `catalog.py` | 设备型号目录（接口数量、console 端口分配规则） |
| `layout.py` / `render.py` | 拓扑自动布局与预览图渲染 |
| `validate.py` / `verify.py` / `xmlio.py` / `export.py` | 拓扑校验、实验验收、XML 读写、导出 |

## 依赖

- `mcp >= 1.26.0, < 2`（MCP 官方 SDK）
- `pillow >= 9.0.0`（拓扑渲染）
- `telnetlib3 >= 4.0.1, < 5`（console 连接）

## 运行方式

已在本机注册（`~/.workbuddy/mcp.json`）：

```json
{
  "mcpServers": {
    "ensp-mcp": {
      "command": "C:\\Users\\agnay\\.venvs\\ensp-mcp\\Scripts\\python.exe",
      "args": ["-m", "ensp_mcp.server"],
      "env": {}
    }
  }
}
```

也提供命令行入口：`ensp-mcp`（服务端）与 `ensp-mcp-doctor`（环境自检）。
