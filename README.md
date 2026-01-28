# Burp Passive XSS Scanner

[中文](#中文) | [English](#english)

---

<h2 id="中文">中文介绍</h2>

# Burp Passive XSS Detector
一个用于 Burp Suite 的 XSS 辅助插件：在不影响正常抓包体验的前提下，对流量做被动分析 + 轻量验证；只有在“可执行反射”成立时才提示 **XSS成功**，并提供参数 fuzz、Header fuzz、右键选中内容 fuzz、去重与防自循环等能力。

> 免责声明：本项目仅用于授权范围内的安全测试与学习研究。请遵守当地法律与目标系统的授权政策，作者不对任何滥用行为负责。
>

---

## Features
+ **被动参数 fuzz（GET/POST）**
    - 自动对请求参数注入 payload 发包验证
    - 支持“暴力 fuzz”模式：对所有参数名进行 fuzz
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590675183-411dca51-958b-4814-9166-7afe567d50d6.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769592419682-e42ebe84-f6fe-48b1-8888-8233d76b47fc.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769592434703-9923a9d7-d128-47fb-86d8-dd72cb431940.png)
    - 对请求包中每个参数进行fuzz
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769598957122-bae6c023-4ba0-44cd-8bcf-fe7387a967db.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769598974895-a7b25f00-f8b0-48f7-af26-5372c02e0e06.png)
    - 支持json请求
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769599737646-0563a140-9196-42bc-af40-e4ce264bedbf.png)
    - 
+ **Header fuzz（可选）**
    - 勾选后自动对 `User-Agent` / `Referer` / `Cookie` 执行 fuzz
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590800711-301468e3-e3b9-48c7-9422-5b5b02fa1dc7.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590818983-f1730056-8ab8-429d-a248-f8663debf2ec.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590834542-0d5b6b2c-c86f-4a6d-bc51-617a10a2aef6.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590839843-3e2ba47e-a20d-4cc0-ab8b-30b0f7c7ff1d.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590860871-27b1ae96-c3bf-463b-b529-1ee2b5acd0c3.png)
+ **右键选中内容 fuzz（全局）**
    - 在 Burp 的任意请求编辑/查看区域选中一段内容 → 右键发送到 fuzz
    - 对“选中的字节范围”直接替换注入，不要求必须是参数值
    - 这里对user-agent进行替换
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590565326-0b289575-3505-4b1e-a515-227e387080dc.png)
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590596563-60af501b-ac54-49ed-9b7c-f8d8d406c816.png)
+ **XSS 成功判定更严格**
    - 不再以“出现反射”就算成功，而是以更像“可执行反射”（标签/事件/JS URL/脚本上下文）为准，降低误报
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769600244191-1dd0bf5b-0a6f-42b7-9d41-2be82d9f71aa.png)
+ **命中停止（hit-stop）**
    - 同一个目标点一旦触发成功，停止继续尝试其它 payload，减少发包量
    - <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769590544097-61005de6-8965-4a44-8b9c-e9c9f8e4a68e.png)
+ **黑名单设置**

    设置相关黑名单，避免误报

    <!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769600780806-58bcf751-c11e-422d-a1a1-d81528ee485e.png)

<!-- 这是一张图片，ocr 内容为： -->
![](https://cdn.nlark.com/yuque/0/2026/png/12881774/1769600795681-3b4af434-d659-4eb7-ab5b-c90a25cef16f.png)

+ **防自循环与去重**
    - 给插件自身发出的请求加标记头，避免自己的 fuzz 请求再次触发 fuzz
    - 同一路径下按“参数名集合”去重：避免 `aaa=1`、`aaa=2` 反复 fuzz
    - 按 path / path+query 去重：降低噪音
+ **性能优化**
    - 线程池队列满时丢弃新任务，避免卡顿
    - 线程池空闲后自动退出，减少内存占用
    - 关键后台线程设为 daemon，任务结束不残留

---

## 目录结构
+ `src/main/java/burp/BurpExtender.java`：核心实现
+ `src/main/resources/easyXssPayload.txt`：payload 词库
+ `lib/`：Burp Extender API jar（编译依赖）
+ `target/burp-passive-xss.jar`：构建产物（编译后生成）

---

## 环境要求
+ Java 8（JDK 8）
+ Burp Suite（社区版/专业版均可加载扩展）
+ Windows / macOS / Linux 均可（示例命令以 Windows PowerShell 为主）

---

## Build（本项目推荐的本地编译方式）
> 如果你的环境没有 Maven，本项目可直接用 `javac` 构建。
>

在项目目录执行：

```powershell
# 进入项目目录
cd .\burp-passive-xss

# 编译
New-Item -ItemType Directory -Force -Path target\classes | Out-Null
javac -encoding UTF-8 -cp lib\burp-extender-api-1.7.22.jar -d target\classes src\main\java\burp\BurpExtender.java

# 拷贝资源（payload 词库）
Copy-Item -Force src\main\resources\easyXssPayload.txt target\classes\easyXssPayload.txt

# 打包 jar
jar cf target\burp-passive-xss.jar -C target\classes .
```

---

## Load into Burp
1. Burp → **Extender** → **Extensions** → **Add**
2. Extension type 选择 **Java**
3. 选择构建出的 `target/burp-passive-xss.jar`
4. 加载后会出现新 Tab：**Passive XSS**

---

## 使用说明
### 1）自动参数 fuzz（GET/POST）
+ 插件启用后，会对符合条件的响应进行候选判断，然后对参数注入 payload 发包验证。
+ 若发现 **XSS成功**，会在表格中新增一条记录，并可查看对应 Request/Response。

### 2）Header fuzz（自动）
+ 在设置栏勾选 **Header fuzz**
+ 插件会在自动 fuzz 阶段同时对以下 Header 进行 fuzz：
    - `User-Agent`
    - `Referer`
    - `Cookie`（优先替换 `user=`，否则追加 `user=<payload>`）

### 3）右键选中内容 fuzz（全局）
+ 在 Burp 的请求区域（如 Proxy/Repeater/Intruder 的 request editor/viewer、history 等）**选中一段内容**
+ 右键 → **Send selection to XSS fuzz**
+ 插件会对“选中范围”执行替换注入并发包验证

> 说明：如果选区来自响应区域，无法定位回请求字节范围时，插件会退回到“匹配参数值后 fuzz”的模式。
>

---

## 配置项说明
+ **Passive fuzz**：总开关
+ **Threads / Queue**：并发与队列（队列满会丢弃新任务，避免卡顿）
+ **Passive max/param**：单参数最多尝试 payload 数
+ **Txt payload limit (0=all)**：txt 词库使用条数（0 = 全部）
+ **Active max/point**：主动扫描插入点最大尝试数（若你在 Burp 主动扫描中启用）
+ **Brute fuzz**：对所有参数名进行 fuzz（更强更吵）
+ **Header fuzz**：对 UA/Referer/Cookie 自动 fuzz
+ **Clear hit-stop**：清空命中停止集合（允许目标再次尝试）
+ **Clear selected / Clear history**：清理 UI 记录（异步执行）

---

## Payload 词库（easyXssPayload.txt）
+ `easyXssPayload.txt` 支持自定义扩展
+ 插件会优先尝试内置 payload，再尝试 txt 词库
+ 部分 payload 会进行必要的编码处理（例如用于 URL 场景时）

---

## XSS 成功判定策略
本插件只在响应中观察到更像“可执行”的反射时才判定 **XSS成功**，例如：

+ 标签注入（`<script` / `<svg` / `<img` / `<iframe` 等）
+ 事件属性（`onload=` / `onclick=` / `onerror=` 等）且处于标签/属性上下文
+ `javascript:` 出现在 `href/src/action/...` 等上下文
+ `<script>` 脚本上下文中出现可执行特征（如 `alert(` / `eval(` 等）

---

## 性能与稳定性说明
+ 线程池：
    - 预启动核心线程减少首次卡顿
    - 队列满时丢弃新任务避免阻塞
    - **空闲后核心线程自动退出**，减少长期内存占用
+ 一次性后台任务线程均为 daemon，任务完成后不残留

---

## 已知限制
+ “是否真正弹窗执行”无法在 Burp 侧直接运行浏览器 JS，因此成功判定基于“可执行反射”启发式规则，仍可能存在少量误判/漏判。
+ 选中内容 fuzz 在响应选区时无法做字节级替换注入，会退化为参数匹配模式。

---

<h2 id="english">English Description</h2>

A Burp Suite extension for XSS detection: performs passive traffic analysis + lightweight verification without affecting the normal proxy experience. Only reports **XSS Success** when "executable reflection" is confirmed. Offers parameter fuzzing, header fuzzing, right-click selection fuzzing, deduplication, and anti-self-loop capabilities.

&gt; Disclaimer: This project is intended for authorized security testing and educational research only. Please comply with local laws and target system authorization policies. The author is not responsible for any misuse.

---

## Features

+ **Passive Parameter Fuzzing (GET/POST)**
  - Automatically injects payloads into request parameters for verification
  - Supports "Brute Fuzz" mode: fuzz all parameter names
  - Fuzz each parameter in the request
  - Supports JSON requests

+ **Header Fuzzing (Optional)**
  - Automatically fuzzes `User-Agent` / `Referer` / `Cookie` when enabled

+ **Right-click Selection Fuzzing (Global)**
  - Select any text in Burp's request editor/viewer → Right-click to send to fuzzer
  - Directly replaces the selected byte range with injection payloads
  - Not limited to parameter values

+ **Strict XSS Success Determination**
  - No longer flags mere "reflection" as success
  - Determines based on "executable reflection" (tags/events/JS URL/script context) to reduce false positives

+ **Hit-Stop Mechanism**
  - Stops further payload attempts once a target point triggers successfully, reducing request volume

+ **Blacklist Settings**
  - Configure blacklists to avoid false positives

+ **Anti-Self-Loop & Deduplication**
  - Adds marker headers to extension-generated requests to prevent fuzzing its own traffic
  - Deduplicates based on "parameter name set" under the same path (avoids repeated fuzzing of `aaa=1`, `aaa=2`)
  - Deduplicates by path / path+query to reduce noise

+ **Performance Optimization**
  - Drops new tasks when thread pool queue is full to avoid lag
  - Core threads automatically exit after idle to reduce memory footprint
  - Background threads marked as daemon, leaving no residue after task completion

---

## Directory Structure

+ `src/main/java/burp/BurpExtender.java`: Core implementation
+ `src/main/resources/easyXssPayload.txt`: Payload wordlist
+ `lib/`: Burp Extender API jar (compile dependency)
+ `target/burp-passive-xss.jar`: Build artifact (generated after compilation)

---

## Requirements

+ Java 8 (JDK 8)
+ Burp Suite (Community or Professional Edition)
+ Windows / macOS / Linux (commands in examples use Windows PowerShell)

---

## Build (Recommended Local Compilation)

&gt; If you don't have Maven, this project can be built directly with `javac`.

Execute in project directory:

```powershell
# Enter project directory
cd .\burp-passive-xss

# Compile
New-Item -ItemType Directory -Force -Path target\classes | Out-Null
javac -encoding UTF-8 -cp lib\burp-extender-api-1.7.22.jar -d target\classes src\main\java\burp\BurpExtender.java

# Copy resources (payload wordlist)
Copy-Item -Force src\main\resources\easyXssPayload.txt target\classes\easyXssPayload.txt

# Package jar
jar cf target\burp-passive-xss.jar -C target\classes .
```
