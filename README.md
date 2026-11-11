# 受信任设备质量事件回调网关

接收供应商推送的设备质量事件，覆盖**密钥轮换交叉期、原始字节验签、重放/冲突
去重、下游队列故障交接、审计与安全重放**。仅依赖 Python 3.12 标准库；
fixtures 中全部是虚构设备事件与合成密钥，没有真实生产凭据或设备连接。

## 威胁场景与对应实现

| 值班遇到的情况 | 处理方式 | 代码位置 |
| --- | --- | --- |
| 轮换签名密钥，旧密钥仍签署在途通知 | 密钥带 `valid_from/retired_at`，交叉期新旧同时在效；按“声明 key_id 优先、新密钥优先”的确定顺序验签，记录**实际采用的 key_id** | `app/security.py` |
| 先解析 JSON 再重编码验签 | 验签始终作用于请求**原始字节**；带长度前缀的 `SIG-V1` 分帧覆盖 `sent_at + event_id + raw_body`，JSON 解析在验签之后 | `app/security.py`, `app/service.py` |
| 时间戳过旧/过远 | 可配置时间窗（默认 300s，绝对值比较），越界拒绝并留拒绝记录 | `app/service.py` |
| 超时重发被算两次 | event_id 唯一主键 + 单条 `BEGIN IMMEDIATE` 事务原子查重；相同字节返回幂等 200，不再入队 | `app/ledger.py` |
| 相同 ID、不同正文 | 判定为冲突（409），保留双方 SHA-256、签名与原始字节证据，不按普通重放吞掉 | `app/ledger.py` |
| 多工作进程并发收到重试 | SQLite WAL + 写事务串行化，同一 event_id 恰好一个 accepted，其余 duplicate/conflict | `tests/test_concurrency.py` |
| 下游队列暂时不可用 | 事件先持久化进接收账本再应答 202；outbox 泵按指数退避重试，租约超时可回收，恢复后不丢事件、不产生重复副作用 | `app/delivery.py` |
| 需要查原始事件去向 | `GET /audit/events/{id}` 返回事件、全部观察记录、交付尝试、冲突证据 | `app/http_server.py` |
| 人工安全重放 | `POST /admin/events/{id}/replay`（admin token），**沿用原始签名证据**，只产生新的交付尝试；挂住的旧尝试标记 superseded | `app/ledger.py`, `app/delivery.py` |

账本表结构只保存 `key_id` 与签名证据，**不保存任何密钥本身**；
`tests/test_service.py` 会直接扫描数据库文件断言密钥字节从未落盘。

## 签名格式（SIG-V1）

```
b"SIG-V1|" + 对 (sent_at ASCII, event_id ASCII, 原始正文 bytes)
依次写入 [8 字节大端长度][字段字节]，整体做 HMAC-SHA256，十六进制传输
```

长度前缀使字段拼接无歧义；任何对正文的字节级改动（包括语义等价的 JSON
重排/空白变化）都会使原签名失效。请求头：

| 头 | 含义 |
| --- | --- |
| `X-Event-Id` | 供应商事件标识（`[A-Za-z0-9_-]{1,128}`） |
| `X-Sent-At` | 发送时间，epoch 秒 ASCII |
| `X-Key-Id` | 发送方声明的密钥版本（交叉期用于优先尝试） |
| `X-Sig-Version` | 可选，缺省为 `SIG-V1` |
| `X-Signature` | HMAC-SHA256 十六进制签名 |

## HTTP 接口

- `POST /callbacks/quality-event`：回调入口，原始字节处理
- `GET  /audit/events/{event_id}`：单事件审计记录（不存在返回 404）
- `POST /admin/events/{event_id}/replay`：安全重放，需 `X-Admin-Token`
- `GET  /healthz`：存活与待交付计数

## 本地运行

```sh
# 1) 生成合成密钥、虚构事件与已签名样例（可重复执行，幂等覆盖）
python3 -I scripts/generate_fixtures.py

# 2) 测试（隔离模式；也支持 python3 -m unittest discover -s tests -v）
python3 -I run_tests.py

# 3) 编译检查与原有离线读取入口
python3 -m compileall -q app tests scripts
python3 -m app.inspect

# 4) 启动演示服务（runtime/ 已在 .gitignore）
python3 -I -m app.http_server --keys fixtures/keystore.json \
    --db runtime/events.db --queue-dir runtime/queue \
    --admin-token synthetic-admin-token
```

## 样例覆盖的场景（`fixtures/signed-samples/`，全部为合成数据）

- `a-signed-old-key / a-signed-new-key`：交叉期同一事件的新旧密钥签名
- `a-redelivery`：同 ID 同字节重发（幂等）
- `a-conflict-body`：同 ID 不同字节正文（冲突留证）
- `a-reencoded-tampered`：保留原签名、仅重编码正文（验签失败）
- `a-stale-timestamp`：超出时间窗
- `a-future-key`：尚未生效的密钥签名
- `b-* / c-*`：其他虚构产线事件

测试矩阵对应：轮换交叉期、字节级差异、多进程/多线程并发重复投递、
队列故障与恢复、租约回收、管理端重放与审计查询。

## 目录

```
app/            接收服务（security / ledger / delivery / service / http_server）
scripts/        合成样例生成器
fixtures/       虚构事件、合成密钥、已签名请求（只读样例）
tests/          单元与端到端测试
runtime/        运行期数据库与本地队列（不入库）
```
