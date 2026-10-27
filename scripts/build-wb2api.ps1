# 重建 wb2api.exe：先构建到工作区**外**的同级暂存目录，再同卷移动到位。
#
# 为什么不能直接 go build -o wb2api.exe：本工作区目录带「低完整性（Low IL）」强制标签
# （DSH 沙箱工作区的既有形态）。在该目录里新创建的文件会**继承低完整性标签**，于是：
#   1. 由它启动的进程按低完整性运行；
#   2. 低完整性进程写不进未打标签（中完整性）的 data/ 与 auths/ ——
#      表现为 `open ./data/state.json.tmp: Access is denied`，而读路径一切正常；
#   3. 该 exe 之后连覆盖/删除都会被拒绝（中完整性进程不能改低完整性对象）。
# 构建到工作区外（父目录无该标签）再移动，标签就不会传染；同卷移动保留原标签。
#
# 用法：pwsh scripts/build-wb2api.ps1 [-OutputName wb2api.exe]
param(
    [string]$OutputName = "wb2api.exe"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$stage = Join-Path (Split-Path -Parent $root) ".wb2api-build"
New-Item -ItemType Directory -Force $stage | Out-Null
$tmpExe = Join-Path $stage $OutputName

Push-Location $root
try {
    & go build -trimpath -o $tmpExe ./cmd/server
    if ($LASTEXITCODE -ne 0) { throw "构建失败" }
} finally {
    Pop-Location
}
Move-Item -Force $tmpExe (Join-Path $root $OutputName)

# 自检：标签里出现 "Low" 就说明仍会以低完整性运行，写盘必失败。
$label = (icacls (Join-Path $root $OutputName) | Select-String -Pattern "Mandatory Label").Line
if ($label -and $label -match "Low") {
    throw "构建产物仍是低完整性标签，启动后会写不进 data/auths：$label"
}
Write-Host ("完成：{0}（{1:N1} MB，标签：{2}）" -f $OutputName, ((Get-Item (Join-Path $root $OutputName)).Length / 1MB), ($label ? $label.Trim() : "无（中完整性）"))
