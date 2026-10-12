"""证据引用守线：文档与技能卡里写的 call_id / 证据路径必须可核对。

两条不变量（D34 定，配套《技能补卡清单》与各卡「证据边界」）：

1. **形状**：写成具体值的 `call_id` 必须是运行层真正会生成的形状 ——
   `src/runtime/runner.py::new_call_id()` = `call-YYYYMMDDTHHMMSS-<6 位十六进制>`，多步适配器再补 `-<标签>`。
   省略式缩写（`call-…f07418`）和占位符（`call-<stamp>-<token>`）是允许的写法，不参与比对；
   但一旦写成 `call-20260915-001` 这种「看起来像真 id」的形状，就必须规范。
2. **可核对**：`output/runs/...` 引用 —— 只要它指向的那次 run 还在本机，被引用的路径就必须真实存在。
   产物已清理（或换了机器）时该条自动跳过：这条守线的价值是拦住「写了个不存在的证物」，
   而不是要求每台机器都保留全部产物。
"""

import re
import unittest

from tests.support import ROOT

CALL_ID = re.compile(r"^call-\d{8}T\d{6}-[0-9a-f]{6}(?:-[0-9a-z]+)*$")
# 宽松匹配只认「以数字开头」的 token：`call-…f07418`、`call-<stamp>` 这类缩写/占位符不在内
CALL_ID_LOOSE = re.compile(r"call-\d[0-9A-Za-z_<>-]*")
EVIDENCE = re.compile(r"output/runs/[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*")


def scanned_files():
    """文档与卡片：证据引用只该出现在这些地方（源码 / 测试里的假 id 不在此列）。"""
    files = [path for folder in ("docs", "skills") for path in sorted((ROOT / folder).rglob("*.md"))]
    files += sorted((ROOT / "skills").rglob("skill.json"))
    files += [ROOT / "scripts" / "README.md", ROOT / "README.md"]
    return [path for path in files if path.is_file()]


def relative(path):
    return path.relative_to(ROOT).as_posix()


class CallIdShapeTests(unittest.TestCase):
    def test_concrete_call_ids_use_the_runner_shape(self):
        offenders = []
        for path in scanned_files():
            text = path.read_text(encoding="utf-8")
            for match in CALL_ID_LOOSE.finditer(text):
                if not CALL_ID.match(match.group(0)):
                    offenders.append(f"{relative(path)}: {match.group(0)}")
        self.assertEqual([], offenders, "call_id 形状与 src/runtime/runner.py::new_call_id() 不一致")


class EvidenceReferenceTests(unittest.TestCase):
    def test_referenced_evidence_paths_exist_while_the_run_is_on_disk(self):
        runs = ROOT / "output" / "runs"
        checked = 0
        skipped = 0
        broken = []
        for path in scanned_files():
            for match in EVIDENCE.finditer(path.read_text(encoding="utf-8")):
                reference = match.group(0).rstrip("/")
                run_dir = runs / reference.split("/")[2]
                if not run_dir.exists():
                    # 产物没保留（output/ 不进 git）：这条引用本轮无从核对
                    skipped += 1
                    continue
                checked += 1
                if not (ROOT / reference).exists():
                    broken.append(f"{relative(path)}: {reference}")
        self.assertEqual([], broken, f"{len(broken)} 条证据引用指向不存在的产物（已核对 {checked} 条）")
        if not checked:
            self.skipTest(f"本机没有保留任何被引用的 run 产物：没有可核对的对象（跳过 {skipped} 条）")


if __name__ == "__main__":
    unittest.main()
