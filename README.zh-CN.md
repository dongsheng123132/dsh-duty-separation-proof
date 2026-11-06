# dsh-duty-separation-proof

作者 / 维护者：贺去病（贺方升 / Dosen）· [hequbing.com](https://www.hequbing.com)

一个离线、确定性的 DSH 职责分离证据层。它只核验调用方明确提供的工作流账本：请求、审批、执行、观察的固定次序，同一工作流/对象绑定，回执链连续性，冲突职责主体不重合，审批人数、主体/观察者多样性以及证据新鲜度。输出仅为脱敏、内容寻址 JSON 判决。

它不是权限或审批系统：不授予角色、不批准请求、不执行变更、不认证主体或回执、不查询线上系统，也不声称 supplied ledger 覆盖了全部真实动作。

## 互补边界

`dsh-guarded-hcl` 的职责分离针对优化器、评估器、策略和提交控制器；`dsh-decision-effect-proof` 回对授权决定与效果；`dsh-artifact-promotion-proof` 回对制品晋级链；`dsh-access-review-proof` 回对权限再认证闭合。本插件只回答一个更窄的问题：**提供的哈希链工作流回执是否满足显式职责冲突策略？**

## 使用

```sh
npm test
npm run check
node bin/dsh-duty-separation-proof.mjs inspect examples/settled.json
node bin/dsh-duty-separation-proof.mjs verify examples/settled.json
```

DSH 工具为 `dsh_duty_separation_inspect` 和 `dsh_duty_separation_verify`；独立 MCP stdio 提供等价的只验证工具。报告会明确保留 `authenticatesReceipts: false`、`provesLedgerExhaustive: false` 与 `provesAbsenceOfUndeclaredActions: false`。

MIT 许可。
