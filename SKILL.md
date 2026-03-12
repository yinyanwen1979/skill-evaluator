---
name: skill-evaluator
description: "根据《The Complete Guide to Building Skills for Claude》标准评估 Skills 的规范性、完整性和安全性。Use when user asks to evaluate a skill, review skill quality, assess new skills, check skill compliance, or audit a skill for safety before installation."
metadata:
  {
    "version": "2.2.0",
    "author": "ranni_openclaw",
  }
---

# Skill Evaluator v2.2

根据 Anthropic 官方指南 + 安全审计标准，评估 Skills 的质量，安全性和合规性。

## 工作流程

评估一个 Skill 遵循以下阶段：

1. **解析输入** - 定位 Skill 目录
2. **静态扫描** - 运行自动化安全扫描（带智能过滤）
3. **内容分析** - 检查结构和内容
4. **风险评估** - 生成评分和判断
5. **报告输出** - 结构化评估报告

## 使用方法

```bash
python3 scripts/evaluate_skill.py /path/to/skill-folder
python3 scripts/evaluate_skill.py https://example.com/skill.zip
```

## 评估维度

### 1. 目录结构检查
- SKILL.md 文件存在性（必需）
- scripts/ references/ assets/ 目录（可选）
  - assets/ 用于模板文件（如评估卡片模板）
- 无 README.md（应放在 references/）

### 2. YAML Frontmatter 验证
- name 字段 kebab-case
- description 包含触发短语
- description 具体详细

### 3. 安全性扫描（智能版）

#### 风险模式检测
- 代码执行: eval, exec, subprocess, pickle
- 网络请求: requests, urllib, curl, wget
- 文件系统: ~/.ssh, /etc, rm -rf
- 权限提升: sudo, chmod 777
- 混淆: base64, hex encoding
- 提示注入: "Ignore previous", "You are now"
- 凭证暴露: API key, password, token

#### 智能过滤（避免误报）
1. **扫描器自身排除**: 扫描器代码中的模式定义不算危险
2. **文档列举过滤**: security-checklist.md 中的列举不算注入
3. **上下文判断**: 区分"定义"和"使用"
   - base64 用于报告生成（HTML内嵌）→ 正常
   - base64 用于混淆payload → 危险
4. **注释/字符串中的模式**: 不在代码执行路径中的不算

### 4. 内容质量评估
- Skill 类型识别（Category 1/2/3）
- 包含代码示例
- 包含错误处理/Troubleshooting

## 风险分级

| 风险等级 | 标准 |
|----------|------|
| SAFE | 无实际风险 |
| LOW | 轻微模式，有合理解释 |
| MEDIUM | 需审查 |
| HIGH | 真正风险 |
| CRITICAL | 严重威胁 |

---

**版本**: 2.2.0  
**更新**: 符合官方标准 - YAML分隔符、XML标签检测、references目录、WHAT/WHEN检查
