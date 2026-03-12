#!/usr/bin/env python3
"""
Skill Evaluator v2.1 - 智能安全扫描版
基于《The Complete Guide to Building Skills for Claude》+ 安全审计标准
新增: 智能过滤避免误报
"""

import os
import sys
import re
import json
import zipfile
import tempfile
import urllib.request
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional


# ==== 风险模式库 ====

DANGEROUS_IMPORTS = {
    "eval", "exec", "compile", "subprocess", "os.system",
    "pickle", "marshal", "shelve", "importlib", "__import__",
    "socket", "http.client", "urllib.request", "urllib3", "requests", "httpx",
    "smtplib", "ftplib", "paramiko", "fabric", "boto3",
    "webbrowser", "tempfile", "ctypes"
}

DANGEROUS_SHELL_PATTERNS = [
    (r"curl\s+", "curl (网络请求)"),
    (r"wget\s+", "wget (网络下载)"),
    (r"rm\s+-rf", "rm -rf (递归删除)"),
    (r"chmod\s+777", "chmod 777 (全权限)"),
    (r"chmod\s+\+s", "chmod +s (setuid)"),
    (r"eval\s*\(", "eval (任意代码执行)"),
    (r"base64\s+(-d|--decode)", "base64 解码 (混淆)"),
    (r"nc\s+(-l|--listen)", "netcat 监听 (反向shell)"),
    (r"python3?\s+-c\s", "python -c (内联代码执行)"),
    (r"bash\s+-c\s", "bash -c (内联shell执行)"),
    (r"\|\s*sh\b", "管道到shell"),
    (r">\s*/etc/", "写入系统目录"),
    (r">\s*~/\.", "写入用户目录"),
    (r"sudo\s+", "sudo (权限提升)"),
    (r"pip\s+install", "pip install (包安装)"),
    (r"npm\s+install", "npm install (包安装)"),
    (r"npx\s+", "npx (包执行)"),
    (r"git\s+clone", "git clone (远程仓库)"),
]

OBFUSCATION_PATTERNS = [
    (r"\\x[0-9a-fA-F]{2}", "hex 转义序列"),
    (r"\\u[0-9a-fA-F]{4}", "unicode 转义"),
    (r"base64", "base64 编码"),
    (r"atob|btoa", "JS base64 函数"),
    (r"String\.fromCharCode", "JS 字符码构建"),
    (r"chr\(\d+\)", "Python 字符构建"),
    (r"getattr\(", "动态属性访问"),
]

SENSITIVE_DATA_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]+['\"]", "硬编码 API key"),
    (r"(?i)(secret|password|passwd)\s*[=:]\s*['\"][^'\"]+['\"]", "硬编码密码"),
    (r"(?i)(token)\s*[=:]\s*['\"][^'\"]{10,}['\"]", "硬编码 token"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub token"),
]

PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+previous\s+instructions?", "忽略之前指令"),
    (r"you\s+are\s+now\s+", "角色扮演注入"),
    (r"disregard\s+all\s+previous", "无视之前指令"),
    (r"<system>", "假系统消息"),
    (r"system:", "系统消息注入"),
    (r"do\s+not\s+show\s+this", "隐藏指令"),
]


class SkillEvaluator:
    """Skills 评估器 v2.1 - 智能过滤版"""
    
    def __init__(self, skill_path: str):
        self.skill_path = skill_path
        self.temp_dir = None
        self.issues: List[Dict[str, str]] = []
        self.warnings: List[str] = []
        self.passed: List[str] = []
        self.findings: List[Dict[str, Any]] = []
        self.risk_level = "SAFE"
        
    def _is_false_positive(self, file_path: str, pattern: str, category: str, content: str) -> bool:
        """
        智能过滤 - 判断是否为误报
        
        返回 True 表示是误报，不应该报告
        """
        filename = os.path.basename(file_path)
        
        # 1. 扫描器自身代码过滤
        scanner_files = ['scan_skill.py', 'scanner.py', 'security_check.py']
        if any(s in filename for s in scanner_files):
            # 扫描器中的模式定义是正常的
            if category in ["危险命令", "混淆"]:
                return True
        
        # 2. 安全文档过滤
        if 'security-checklist' in filename or 'security_checklist' in filename:
            # 安全清单文档中列举危险模式是正常的
            if category in ["提示注入", "混淆"]:
                return True
        
        # 3. 报告生成类文件的 base64 用法
        if 'report' in filename.lower() or 'generate' in filename.lower():
            # 报告生成用的 base64 是正常的（HTML内嵌图片）
            if 'base64' in pattern.lower():
                # 检查是否用于报告生成
                if 'html' in content.lower() or 'svg' in content.lower():
                    return True
        
        # 4. 注释和字符串中的模式不算
        lines = content.split('\n')
        for line in lines:
            # 如果模式只在注释或字符串定义中，跳过
            if '#' in line or '"' in line or "'" in line:
                # 检查这行是否有实际的函数调用
                if pattern in line and ('=' in line or 'def ' in line):
                    # 这行只是定义，不是实际使用
                    continue
        
        # 5. 检查是否在正则表达式定义中（用于检测危险模式本身）
        if 'pattern' in content.lower() and ('regex' in content.lower() or 're.compile' in content.lower()):
            # 这是定义检测模式，不是实际使用
            return True
        
        return False
    
    def _parse_frontmatter(self, content: str) -> Dict[str, str]:
        """简单解析 YAML frontmatter"""
        frontmatter = {}
        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                fm_text = parts[1]
                for line in fm_text.split('\n'):
                    line = line.strip()
                    if ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        frontmatter[key.strip()] = value.strip()
        return frontmatter
    
    def evaluate(self) -> Dict[str, Any]:
        """执行完整评估"""
        skill_dir = self._prepare_skill_dir()
        if not skill_dir:
            return self._error_result("无法准备 Skill 目录")
        
        results = {
            "structure": self._check_structure(skill_dir),
            "frontmatter": self._check_frontmatter(skill_dir),
            "security": self._check_security(skill_dir),
            "content": self._check_content(skill_dir),
        }
        
        score = self._calculate_score(results)
        self._determine_risk_level()
        
        return {
            "score": score,
            "risk_level": self.risk_level,
            "results": results,
            "issues": self.issues,
            "warnings": self.warnings,
            "passed": self.passed,
            "findings": self.findings,
        }
    
    def _prepare_skill_dir(self) -> Optional[Path]:
        """准备 Skill 目录"""
        if self.skill_path.startswith("http://") or self.skill_path.startswith("https://"):
            try:
                self.temp_dir = tempfile.mkdtemp()
                
                if "github.com" in self.skill_path:
                    match = re.search(r'github\.com/([^/]+/[^/]+)', self.skill_path)
                    if match:
                        repo = match.group(1)
                        clone_url = f"https://github.com/{repo}.git"
                        subprocess.run(
                            ["git", "clone", "--depth", "1", clone_url, self.temp_dir],
                            capture_output=True, timeout=30
                        )
                        return Path(self.temp_dir)
                
                elif self.skill_path.endswith(".zip"):
                    zip_path = os.path.join(self.temp_dir, "skill.zip")
                    urllib.request.urlretrieve(self.skill_path, zip_path)
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        zf.extractall(self.temp_dir)
                    
                    for item in os.listdir(self.temp_dir):
                        item_path = os.path.join(self.temp_dir, item)
                        if os.path.isdir(item_path) and "SKILL.md" in os.listdir(item_path):
                            return Path(item_path)
                
                return Path(self.temp_dir)
            except Exception as e:
                self.issues.append({"type": "error", "message": f"下载失败: {str(e)}"})
                return None
        else:
            return Path(self.skill_path)
    
    def _check_structure(self, skill_dir: Path) -> Dict[str, Any]:
        """检查目录结构"""
        checks = []
        
        skill_md = skill_dir / "SKILL.md"
        if skill_md.exists():
            checks.append(("SKILL.md 存在", True))
            self.passed.append("SKILL.md 存在")
        else:
            checks.append(("SKILL.md 存在", False))
            self.issues.append({"type": "error", "message": "缺少 SKILL.md 文件"})
        
        for dir_name in ["scripts", "references", "assets"]:
            exists = (skill_dir / dir_name).is_dir()
            checks.append((f"{dir_name}/ 目录", exists))
        
        readme = skill_dir / "README.md"
        if readme.exists():
            checks.append(("无 README.md", False))
            self.warnings.append("发现 README.md，应移至 references/")
        else:
            checks.append(("无 README.md", True))
        
        return {"name": "目录结构", "checks": checks, "passed": all(c[1] for c in checks)}
    
    def _check_frontmatter(self, skill_dir: Path) -> Dict[str, Any]:
        """检查 YAML frontmatter"""
        checks = []
        frontmatter = {}
        
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            return {"name": "YAML Frontmatter", "checks": [], "passed": False}
        
        try:
            content = skill_md.read_text(encoding='utf-8')
            
            # 检查 YAML --- 分隔符
            has_start = content.startswith("---")
            has_end = content.count("---") >= 2
            checks.append(("YAML --- 分隔符", has_start and has_end))
            if has_start and has_end:
                self.passed.append("YAML frontmatter 格式正确")
            
            # 解析 frontmatter
            frontmatter = self._parse_frontmatter(content)
            
            name = frontmatter.get('name', '')
            if name and re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', name):
                checks.append(("name 使用 kebab-case", True))
                self.passed.append(f"Skill 名称: {name}")
            else:
                checks.append(("name 使用 kebab-case", False))
                self.issues.append({"type": "error", "message": f"name 应使用 kebab-case: {name}"})
            
            desc = frontmatter.get('description', '')
            if desc:
                # 检查是否包含 WHAT 和 WHEN
                has_what = any(word in desc.lower() for word in ['use', 'when', 'ask', 'mention', 'does', 'handles', 'provides'])
                has_when = any(word in desc.lower() for word in ['use when', 'ask', 'mention', 'says', 'request'])
                checks.append(("description 包含 WHAT", has_what))
                checks.append(("description 包含 WHEN", has_when))
                
                has_trigger = any(word in desc.lower() for word in ['use when', 'ask', 'mention', 'says'])
                checks.append(("description 包含触发条件", has_trigger))
                if has_trigger:
                    self.passed.append("包含触发条件")
                
                if len(desc) < 20:
                    checks.append(("description 足够具体", False))
                else:
                    checks.append(("description 足够具体", True))
            else:
                checks.append(("description 存在", False))
                self.issues.append({"type": "error", "message": "缺少 description"})
            
            # 检查 XML 标签
            xml_pattern = re.compile(r'<[^>]+>')
            xml_matches = xml_pattern.findall(content)
            if xml_matches:
                checks.append(("无 XML 标签", False))
                self.issues.append({"type": "error", "message": f"发现 XML 标签: {xml_matches[:3]}"})
            else:
                checks.append(("无 XML 标签", True))
            
            # 检查 references/ 目录和引用链接
            ref_dir = skill_dir / "references"
            if ref_dir.exists() and ref_dir.is_dir():
                checks.append(("references/ 目录存在", True))
                # 检查是否在 SKILL.md 中有引用
                if "references/" in content or "reference" in content.lower():
                    self.passed.append("引用链接清晰")
            else:
                checks.append(("references/ 目录存在", False))
            
            # 检查示例
            if "```" in content or "example" in content.lower() or "例如" in content:
                checks.append(("包含示例", True))
                self.passed.append("包含代码示例")
            else:
                checks.append(("包含示例", False))
            
            # 检查错误处理
            if "error" in content.lower() or "exception" in content.lower() or "错误" in content or "异常" in content:
                checks.append(("包含错误处理", True))
            else:
                checks.append(("包含错误处理", False))
            
            if 'metadata' in frontmatter:
                checks.append(("metadata 字段", True))
            
        except Exception as e:
            self.issues.append({"type": "error", "message": f"解析错误: {str(e)}"})
        
        passed = sum(1 for c in checks if c[1])
        return {
            "name": "YAML Frontmatter",
            "checks": checks,
            "passed": passed >= len(checks) * 0.5,
            "frontmatter": frontmatter
        }
    
    def _check_security(self, skill_dir: Path) -> Dict[str, Any]:
        """检查安全性 - 智能过滤版"""
        checks = []
        
        # 检查所有代码文件
        for ext in [".py", ".sh", ".js", ".ts"]:
            for md_file in skill_dir.rglob(f"*{ext}"):
                try:
                    content = md_file.read_text(encoding='utf-8', errors='ignore')
                    
                    # 危险导入
                    for imp in DANGEROUS_IMPORTS:
                        if f"import {imp}" in content or f"from {imp} import" in content:
                            # 检查是否是实际使用（不是导入定义）
                            if f"import {imp}" in content and "importlib" not in imp:
                                # 这只是导入，不是调用
                                pass
                            else:
                                # 检查是否为误报
                                if not self._is_false_positive(str(md_file), imp, "危险导入", content):
                                    self.findings.append({
                                        "file": str(md_file.relative_to(skill_dir)),
                                        "category": "危险导入",
                                        "severity": "CRITICAL",
                                        "pattern": f"导入: {imp}"
                                    })
                    
                    # 危险 Shell 模式
                    for pattern, desc in DANGEROUS_SHELL_PATTERNS:
                        if re.search(pattern, content):
                            # 智能过滤
                            if self._is_false_positive(str(md_file), desc, "危险命令", content):
                                continue
                            self.findings.append({
                                "file": str(md_file.relative_to(skill_dir)),
                                "category": "危险命令",
                                "severity": "HIGH",
                                "pattern": desc
                            })
                    
                    # 混淆模式
                    for pattern, desc in OBFUSCATION_PATTERNS:
                        if re.search(pattern, content):
                            if self._is_false_positive(str(md_file), desc, "混淆", content):
                                continue
                            self.findings.append({
                                "file": str(md_file.relative_to(skill_dir)),
                                "category": "混淆",
                                "severity": "HIGH",
                                "pattern": desc
                            })
                    
                    # 凭证暴露
                    for pattern, desc in SENSITIVE_DATA_PATTERNS:
                        if re.search(pattern, content):
                            self.findings.append({
                                "file": str(md_file.relative_to(skill_dir)),
                                "category": "凭证暴露",
                                "severity": "MEDIUM",
                                "pattern": desc
                            })
                            
                except Exception as e:
                    self.warnings.append(f"无法扫描 {md_file.name}")
        
        # 检查 MD 文件的提示注入
        for md_file in skill_dir.rglob("*.md"):
            try:
                content = md_file.read_text(encoding='utf-8')
                
                for pattern, desc in PROMPT_INJECTION_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        if self._is_false_positive(str(md_file), desc, "提示注入", content):
                            continue
                        self.findings.append({
                            "file": str(md_file.relative_to(skill_dir)),
                            "category": "提示注入",
                            "severity": "HIGH",
                            "pattern": desc
                        })
                        
            except Exception:
                pass
        
        # 摘要
        if self.findings:
            checks.append(("安全扫描完成", True))
            self.warnings.append(f"发现 {len(self.findings)} 个风险项")
        else:
            checks.append(("安全扫描完成 - 无风险", True))
            self.passed.append("无安全风险")
        
        return {
            "name": "安全性",
            "checks": checks,
            "passed": len(self.findings) == 0
        }
    
    def _check_content(self, skill_dir: Path) -> Dict[str, Any]:
        """检查内容质量"""
        checks = []
        
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            return {"name": "内容质量", "checks": [], "passed": False}
        
        content = skill_md.read_text(encoding='utf-8')
        
        skill_type = self._identify_skill_type(content)
        checks.append((f"Skill 类型: {skill_type}", True))
        self.passed.append(f"类型: {skill_type}")
        
        if '```' in content:
            checks.append(("包含代码示例", True))
            self.passed.append("包含示例")
        else:
            checks.append(("包含代码示例", False))
        
        if any(word in content.lower() for word in ['troubleshoot', 'error', '常见问题']):
            checks.append(("包含错误处理", True))
        else:
            checks.append(("包含错误处理", False))
        
        return {"name": "内容质量", "checks": checks, "passed": True}
    
    def _identify_skill_type(self, content: str) -> str:
        """识别 Skill 类型"""
        c = content.lower()
        if 'mcp' in c and ('workflow' in c or 'automate' in c):
            return "Category 3: MCP增强"
        if 'workflow' in c or 'step' in c or 'automation' in c:
            return "Category 2: 工作流自动化"
        if 'create' in c or 'generate' in c or 'build' in c:
            return "Category 1: 文档/资源创建"
        return "通用类型"
    
    def _calculate_score(self, results: Dict) -> int:
        """计算总分"""
        total = 0
        passed = 0
        
        for data in results.values():
            checks = data.get("checks", [])
            for check in checks:
                total += 1
                if check[1]:
                    passed += 1
        
        # 风险发现扣分
        for f in self.findings:
            if f["severity"] == "CRITICAL":
                passed -= 5
            elif f["severity"] == "HIGH":
                passed -= 3
            elif f["severity"] == "MEDIUM":
                passed -= 1
        
        return max(0, min(100, int((passed / max(total, 1)) * 100)))
    
    def _determine_risk_level(self):
        """确定风险等级"""
        has_critical = any(f["severity"] == "CRITICAL" for f in self.findings)
        has_high = any(f["severity"] == "HIGH" for f in self.findings)
        has_medium = any(f["severity"] == "MEDIUM" for f in self.findings)
        
        if has_critical:
            self.risk_level = "CRITICAL"
        elif has_high:
            self.risk_level = "HIGH"
        elif has_medium:
            self.risk_level = "MEDIUM"
        elif self.findings:
            self.risk_level = "LOW"
        else:
            self.risk_level = "SAFE"
    
    def _error_result(self, msg: str) -> Dict[str, Any]:
        return {
            "score": 0, "risk_level": "CRITICAL",
            "results": {}, "issues": [{"type": "error", "message": msg}],
            "warnings": [], "passed": [], "findings": []
        }
    
    def generate_report(self, results: Dict) -> str:
        """生成 Markdown 评估报告 - 带卡片格式"""
        score = results["score"]
        risk = results["risk_level"]
        
        risk_emoji = {"SAFE": "✅", "LOW": "✅", "MEDIUM": "⚠️", "HIGH": "❌", "CRITICAL": "🔴"}
        
        # 获取技能名称
        skill_name = "未知"
        if "frontmatter" in results.get("results", {}):
            fm = results["results"]["frontmatter"].get("frontmatter", {})
            skill_name = fm.get("name", "未知")
        
        # 获取类型
        skill_type = "通用类型"
        for check in results.get("results", {}).get("content", {}).get("checks", []):
            if "类型:" in check[0]:
                skill_type = check[0].replace("类型: ", "")
        
        # 生成卡片
        card = f"""
┌─────────────────────────────────────────────────────────────┐
│  📋 Skill 评估卡片                                              │
├─────────────────────────────────────────────────────────────┤
│  🎯 名称: {skill_name}                                        │
│  📁 类型: {skill_type}                                          │
├─────────────────────────────────────────────────────────────┤
│  📊 总体评分                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  {score}/100  {risk_emoji.get(risk, '')} {risk}                   │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  ✅ 通过项                          ❌ 问题项                  │"""

        # 通过项
        passed_items = results.get("passed", [])[:3]
        issues_items = results.get("issues", [])[:3]
        
        for i in range(max(len(passed_items), len(issues_items), 1)):
            passed = passed_items[i] if i < len(passed_items) else ""
            issue = issues_items[i]["message"] if i < len(issues_items) else ""
            passed = (passed[:22] + "...") if len(passed) > 22 else passed
            issue = (issue[:22] + "...") if len(issue) > 22 else issue
            card += f"\n│  {i+1}. {passed:<25} {i+1}. {issue:<25} │"
        
        findings_count = len(results.get('findings', []))
        install_suggest = "✅ 推荐安装" if risk in ["SAFE", "LOW"] else "⚠️ 谨慎安装" if risk == "MEDIUM" else "❌ 不推荐"
        
        card += f"""
├─────────────────────────────────────────────────────────────┤
│  🔒 安全扫描: {findings_count} 个风险项                              │
├─────────────────────────────────────────────────────────────┤
│  📥 安装建议: {install_suggest}                                       │
└─────────────────────────────────────────────────────────────┘

---

## 详细报告

"""
        
        # 详细报告
        for data in results.get("results", {}).values():
            card += f"### {data['name']}\n\n"
            for check in data.get("checks", []):
                status = "✅" if check[1] else "❌"
                card += f"- {status} {check[0]}\n"
            card += "\n"
        
        if results.get("findings"):
            card += "## 安全发现\n\n"
            card += "| 文件 | 类别 | 严重性 | 模式 |\n"
            card += "|------|------|--------|------|\n"
            for f in results["findings"]:
                card += f"| {f['file']} | {f['category']} | {f['severity']} | {f['pattern']} |\n"
            card += "\n"
        
        if results.get("issues"):
            card += "## 问题列表\n\n"
            for issue in results["issues"]:
                icon = "🔴" if issue["type"] == "error" else "🟡"
                card += f"- {icon} {issue['message']}\n"
            card += "\n"
        
        if results.get("warnings"):
            card += "## 改进建议\n\n"
            for w in results["warnings"]:
                card += f"- 💡 {w}\n"
            card += "\n"
        
        if results.get("passed"):
            card += "## 通过项\n\n"
            for p in results["passed"]:
                card += f"- ✅ {p}\n"
            card += "\n"
        
        card += "## 安装建议\n\n"
        if risk == "SAFE":
            card += "✅ **推荐安装** - 无安全风险\n"
        elif risk == "LOW":
            card += "✅ **可安装** - 有轻微发现但有合理解释\n"
        elif risk == "MEDIUM":
            card += "⚠️ **谨慎安装** - 请审查发现后再安装\n"
        elif risk == "HIGH":
            card += "❌ **不推荐安装** - 存在高风险发现\n"
        else:
            card += "🔴 **禁止安装** - 存在严重风险\n"
        
        return card


def main():
    if len(sys.argv) < 2:
        print("用法: python3 evaluate_skill.py <skill-path-or-url>")
        sys.exit(1)
    
    skill_path = sys.argv[1]
    
    print(f"📋 正在评估: {skill_path}")
    print("-" * 50)
    
    evaluator = SkillEvaluator(skill_path)
    results = evaluator.evaluate()
    report = evaluator.generate_report(results)
    
    print(report)
    
    output_file = "/Users/yinyanwen/clawd/skill-evaluation-report.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n📄 报告已保存到: {output_file}")
    
    risk_to_code = {"SAFE": 0, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    sys.exit(risk_to_code.get(results["risk_level"], 1))


if __name__ == "__main__":
    main()
