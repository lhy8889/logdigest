# logdigest

把几万行日志压成一张表：**每种事件一行**，带出现次数、首次/末次时间和级别。

一个零依赖的 Go 命令行工具，Windows / Linux / macOS 单文件运行。

---

## 它解决什么问题

线上出问题时，第一反应是 `grep ERROR app.log`，然后得到几千行。里面真正**不同**的问题可能只有七八个，剩下全是同一个异常在刷屏——但每一行都带着不同的订单号、耗时、IP，直接 `sort | uniq -c` 也聚不起来。

logdigest 做三件事：

1. **把多行堆栈并回它所属的那条日志**，不让一整个 traceback 变成一个孤立的 `at foo (x.go:214)`；
2. **把易变的部分归一化**：订单号、耗时、IP、UUID、长 hex id 都替换成 `<n>`、`<ip>`、`<uuid>`；
3. **按归一化后的“指纹”计数排序**，同一类事件合并成一行。

### 前后对比

输入（节选，22 行里 3 行是同一个超时的堆栈）：

```
2026-11-05 09:00:11 ERROR upstream timeout after 3001ms calling payment-gateway 10.4.19.7
    at payment.Client.Charge (/srv/app/payment/client.go:214)
    at orders.(*Service).Create (/srv/app/orders/service.go:88)
    at http.HandlerFunc.ServeHTTP (/srv/app/orders/handler.go:41)
...
2026-11-05 09:00:38 ERROR redis: connection refused 127.0.0.1:6379
```

输出：

```
1 file, 20 records, 7 patterns

COUNT  LEVEL  LAST SEEN            PATTERN
    5  info   2026-11-05 09:00:42  INFO GET /health <n> <n>ms
    3  error  2026-11-05 09:00:40  ERROR redis: connection refused <ip>:<n>
    3  info   2026-11-05 09:00:35  INFO POST /orders <n> <n>ms
    3  warn   2026-11-05 09:00:31  WARN slow query took <n>ms: SELECT * FROM orders WHERE id = <n>
    3  error  2026-11-05 09:00:21  ERROR upstream timeout after <n>ms calling payment-gateway <ip> (+3 lines)
    2  error  2026-11-05 09:00:33  ERROR user <uuid> not found in tenant acme
    1  info   2026-11-05 09:00:01  INFO server listening on :<n>
```

上面的输出来自仓库里的 `testdata/app.log`，可以直接复现：

```bash
go run ./cmd/logdigest -top 0 testdata/app.log
```

## 安装

**下载二进制**（推荐）：到 [Releases](https://github.com/lhy8889/logdigest/releases) 下载对应平台的压缩包，解压后直接运行，不需要装 Go。

**用 Go 安装**：

```bash
go install github.com/lhy8889/logdigest/cmd/logdigest@latest
```

**从源码构建**：

```bash
git clone https://github.com/lhy8889/logdigest
cd logdigest
go build -o logdigest ./cmd/logdigest
```

## 用法

```bash
logdigest [flags] [file...]        # 不给文件名时读标准输入
tail -n 50000 app.log | logdigest -top 10
docker logs api 2>&1 | logdigest -since 30m -level error
logdigest -json app.log | jq '.groups[] | select(.level=="error")'
```

| Flag | 默认 | 说明 |
|---|---|---|
| `-top N` | `20` | 只显示前 N 个模式，`0` 显示全部 |
| `-min N` | `1` | 出现次数少于 N 的模式不显示 |
| `-since` | — | 只看这个时间之后的记录：`2h`、`90m`、`2026-11-01`、RFC3339。没有时间戳的行无法定位，会保留 |
| `-level` | — | 只看这个级别及以上的：`error` / `warn` / `info` / `debug` |
| `-json` | `false` | 输出 JSON，便于接 jq 或做告警 |
| `-mask` | `true` | 把样例行里的 IP、邮箱、UUID、长 hex 换成占位符（`-mask=false` 看原样） |
| `-version` | — | 打印版本 |

## 工作原理

1. **切记录**（`internal/digest/record.go`）：识别常见时间戳前缀（ISO、斜杠、方括号、syslog、Apache），有前缀的行开一条新记录，缩进行、`at ...`、`Traceback`、`Caused by:` 之类并入上一条。整个文件都没有时间戳时，退化成一行一条——这符合 `docker logs` 这类输出的直觉。
2. **算指纹**（`fingerprint.go`）：按固定顺序替换 UUID → IP → 邮箱 → 长 hex → 数字，逐行归一化后保留换行拼接。换行保留是有意的：同一条报错配不同堆栈应当算两类。
3. **聚合排序**（`report.go`）：按指纹计数，记录首次/末次时间、最高级别、来源文件；先按次数降序，次数相同按最后出现时间新的在前，保证输出稳定。

## 已知边界

写得清楚比藏起来好：

- 日志**没有时间戳**时，一行算一条，不带缩进的多行事件不会合并；
- 一条记录最多吸收 200 行续行，防止一个丢了换行的文件被吞成一条；
- syslog 格式没有年份，按当前年份补，跨年文件会差一年；
- 目前整份文件读进内存，几 GB 的日志建议先 `tail -n 200000` 截一段；
- 级别是从消息文本里正则匹配的关键字（`ERROR`、`warn`、`panic`…），不是结构化解析，业务消息里出现 "error" 字样的 INFO 行会被认成 ERROR；
- 数字归一化会把 `200 3ms` 变成 `<n> <n>ms`，所以状态码与耗时在指纹里不可区分——这是有意的取舍，聚合优先。

## 开发

```bash
go test ./...        # 33 个测试，覆盖时间戳解析、堆栈归并、指纹归一化、排序、过滤、JSON
go vet ./...
gofmt -l .
```

CI 在 Ubuntu、Windows、macOS 三个平台跑 `gofmt` / `go vet` / `go test`（见 `.github/workflows/ci.yml`）；打 `v*` 标签会交叉编译四个平台的二进制并生成校验和（`.github/workflows/release.yml`）。

## License

MIT
