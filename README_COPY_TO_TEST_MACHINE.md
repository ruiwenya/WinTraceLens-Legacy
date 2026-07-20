# WinTraceLens Legacy 独立测试包

这个目录是 Windows 7 / Windows Server 2012 专用调试工程，不再与 `ir-process-lens` 的 WebView2 版本混在一起。

## 复制文件

只复制这个文件到测试机：

- `D:\codex-program\sec-analysis\wintracelens-legacy\dist\WinTraceLens-legacy.exe`

不要复制 `D:\codex-program\sec-analysis\ir-process-lens\dist` 里的旧文件。

## 本次修复点

Win7 上报错 `TTM_ADDTOOL failed`，原因是 `walk` 自动注册 tooltip 时旧系统 common controls 拒绝注册。Legacy 工程里的 `third_party\walk` 已统一降级处理：tooltip 注册失败时跳过 tooltip，不影响窗口启动。

Win11/Win7 上如果报错 `EM_SETCUEBANNER failed`，原因是输入框占位提示文字设置失败。该功能只是搜索框提示文案，不影响采集能力，当前版本已移除应用层 `CueBanner` 并在 `third_party\walk` 中将该错误降级为可忽略。

## 测试步骤

1. 在 Win7 / Server 2012 测试机上右键“以管理员身份运行”。
2. 确认窗口能打开，不再弹出 `TTM_ADDTOOL failed`。
3. 查看“进程信息”是否自动加载。
4. 切换到“主机信息”，确认首次切换会自动采集；上方按钮可切换“服务 / 计划任务 / 启动项 / 用户 / 镜像劫持”，下面使用同一个表格展示。
5. 切换到“关注项”，确认首次切换会自动分析。
6. 切换到“事件日志”，确认首次切换会按当前日期范围自动读取；旧机器建议日期先选最近 1 天后再点“读取日志”。
7. 测试任意页面“导出 CSV”。

## 反馈信息

如果仍然失败，请截图完整错误窗口，并记录：

- 系统版本
- 是否管理员运行
- 是否安装 .NET / PowerShell 版本
- 错误栈里最后几个 `third_party\walk\*.go` 文件名和行号
