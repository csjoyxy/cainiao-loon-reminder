# 菜鸟驿站每日待取提醒（Loon 插件）

每天下午 **17:30**（可自定义）自动查询名下菜鸟驿站 / 代收点待取快递，若存在未取包裹则弹出系统通知（展示**取件码、快递公司、商品简称、滞留天数**），点击通知**自动复制全部取件码并拉起菜鸟身份码页**；若无待取包裹则静默不打扰。

## 安全与省电特性

1. **零第三方中转**：代码 100% 存放在你自己的仓库，仅直连阿里官方 `https://h5api.m.taobao.com`（且强制指定 `DIRECT` 国内直连策略，即使开着全局代理也不会绕行海外节点触发异地风控）。
2. **日常 0 MitM、0 额外耗电**：仅首次配置时开启 10 秒抓取一次淘宝 H5 登录态；抓完关闭开关与插件 MitM 后，平时不做任何流量拦截解密，每天仅唤醒一次 `< 1 秒` 的轻量请求（`_m_h5_tk` 短期签名令牌会在查询时自动续期）。
3. **存储加密防跨脚本读取**：使用插件私有参数 `vault_pin` 派生独立存储键名并加密保存 Cookie（Loon Build 988+ 自动启用原生 `AES-256-GCM` 认证加密），防止 Loon 内其他第三方脚本遍历 `$persistentStore` 读取明文凭证。

---

## 一键安装与首次配置（仅需 1 分钟）

### 第 1 步：安装插件

在 Loon「**插件**」页面右上角点击 `+`，粘贴以下插件地址安装：

```text
https://raw.githubusercontent.com/csjoyxy/cainiao-loon-reminder/main/cainiao_pickup.lpx
```

> 建议在插件设置里顺手把 **「本地存储隔离口令 (`vault_pin`)」** 改成你自己随便设的一串字符（如 `mybox2026`），进一步隔离本机存储。

### 第 2 步：用手机 Safari 抓一次登录态（10 秒搞定）

1. 确保 Loon 全局 **MitM 总开关**已开启（若之前配置过 Loon HTTPS 证书则无需重复安装证书）。
2. 点进本插件设置页：
   - 打开插件顶部的 **「启用 MitM」**；
   - 打开下方的 **「抓取Cookie临时开关（抓完即关）」**，点击右上角保存。
3. 打开系统 **Safari 浏览器**，访问：
   ```text
   https://h5.m.taobao.com/mlapp/olist.html
   ```
   登录你的淘宝账号（菜鸟包裹列表与同手机号淘宝账号互通）。
4. 看到顶部弹出 **「✅ 菜鸟/淘宝登录态捕获成功」** 的通知后，回到 Loon 本插件设置页：
   - **关闭「抓取Cookie临时开关」**；
   - **关闭本插件顶部的「启用 MitM」**，保存！

### 第 3 步：立即测试验证

在 Loon 插件详情页（或脚本列表）找到 **「立即检测一次待取快递」** 点击运行：
- 若当前有待取件，会立刻弹出包含取件码的通知；
- 若当前无待取件，手动测试也会弹窗提示 **「📭 今日暂无待取快递 · 连接与登录态正常！」**。

验证通过后即可放着不管——此后每天 **17:30** 有待取快递时会自动提醒你，没快递则静默不打扰；万一数周后淘宝登录态自然过期，当天 17:30 也会弹通知提醒你重新刷新一次。

---

## 🛡️ 附：iOS 老版本（16.4.1 等）WebKit 浏览器防投毒插件套件

针对长期停留在 iOS 15–17（如 iOS 16.4.1 巨魔环境）设备的浏览器安全加固，本仓库额外提供**「核心 IOC 零延迟拦截」+「可选恶意域名安全 DoH」**双插件拆分方案，方便按国内网络环境自由组合：

### 1. 核心插件：iOS WebKit 水坑与漏洞链防护（推荐常开 · 国内零延迟）
- **插件地址**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/cainiao-loon-reminder/main/ios_webkit_shield.lpx
  ```
- **独立规则集地址（供 Loon `RULE-SET` / Surge / 路由器复用）**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/cainiao-loon-reminder/main/rules/ios_webkit_ioc.list
  ```
- **特点**：**不修改主配置全局 DNS、0 MitM、0 后台常驻耗电**；精准 `REJECT` 阻断 Google Threat Intelligence (GTIG)、iVerify、Kaspersky 披露的 **Coruna / CryptoWaters**（覆盖 iOS 13–17.2.1 全链 WebKit RCE 与钱包注入模块）、**DarkSword**、**Operation Triangulation（三角行动）** 水坑域名、C2 IP、明文植入载荷路径与 `powerd` 异常外联 UA。
- **一键自检**：装好后可在插件详情页点击 **「立即自检防护与安全DoH延迟」**，1 秒验证本机 `REJECT` 防线是否生效，并实测当前网络直连安全 DoH 的毫秒级延迟。

### 2. 可选插件：iOS 恶意域名拦截安全 DoH（按网络流畅度自由开关）
- **插件地址**：
  ```text
  https://raw.githubusercontent.com/csjoyxy/cainiao-loon-reminder/main/ios_security_doh.lpx
  ```
- **特点**：开启后向 Loon 追加 **Cloudflare Security (`1.1.1.2`)** 与 **Quad9 (`9.9.9.9`)** 实时恶意软件/钓鱼域名拦截加密 DoH（内置静态 Host 引导 IP 防 DNS 抢答）；若当前运营商网络直连海外 DoH 偶有变慢，在 Loon 插件列表**随手关掉本插件开关即可零残留恢复国内解析速度**，不影响上面的核心 IOC 防护插件。

---

## 本地自测

```bash
node tests/test_cainiao_pickup.js
node tests/test_webkit_shield.js
```
