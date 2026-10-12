"""Citation, material and handover checks for lean conclusions."""
from __future__ import annotations

import json
import re

from runtime import dispatch
from runtime.lean_journal import _error
from runtime.redact import mask_secrets
from runtime.runner import ownership


def _fold_ws(text) -> str:
    """**比对用**的引文折叠：先去掉转义层级、再去掉全部空白 —— 落盘原文一个字不动。

    为什么不比空白：模型抄回执时常把 JSON/表格的间距改掉（`"body": "X"` 抄成 `"body":"X"`），
    而**空白布局不是内容**（2026-10-07 walk-82 node 7：8 发全 rc=0、链条跑通、结论也对，
    就因一处空格被判 `LEAN_CITATION_NOT_FOUND`）。

    为什么不比转义：引擎 HTTP 客户端的回执把响应体按 JSON 串存下来，**同一段文本可能比模型看到的
    多一层转义**（`"body": "{\\"status\\":1,…}"` 对应的原话是 `{"status":1,…}`）—— 嵌套一层还是两层
    是记账格式，不是内容。2026-10-07 walk-85 node 7 实测：模型引的正是回执里的真观测，只因为
    回执那层多一次转义被判无效，白烧一格。所以这里**反复去转义直到稳定**，再去空白。
    """
    text = str(text or "")
    while True:
        unescaped = re.sub(r"\\(.)", r"\1", text)
        if unescaped == text:
            break
        text = unescaped
    return re.sub(r"\s+", "", text)


def _raw_offset(raw, quote) -> int:
    """空白折叠匹配时，给一个"引文大概从原文哪里开始"的位置（取它第一个词的位置）。"""
    words = str(quote or "").split()
    head = words[0] if words else ""
    return raw.find(head) if head else 0



class _LeanEvidence:

    @staticmethod
    def _marked(text, marker):
        """哨兵齐不齐；**结束行允许带退出码后缀**（Windows 包装写成 `<marker>end %errorlevel%`）。

        行业惯例那一手（爷爷 2026-10-07）：哨兵只证明"终端走到了这一行"，带上退出码才同时证明
        "命令跑过、成没成"。这里的判断因此是：
          * 只有 `<marker>end`（无码）→ 老包装/无声通道，齐了就算齐；
          * `<marker>end 0` / `<marker>end 5` → 齐，且**码就是命令的退出码**；
          * 结束行整行不出现 → 不齐（没跑或通道坏，如实记 unknown）。
        """
        lines = [line.strip() for line in str(text).splitlines()]
        start, end = marker + "start", marker + "end"
        heads = [line for line in lines if line == end or line.startswith(end + " ")]
        return start in lines and bool(heads) and lines.index(start) < lines.index(heads[0])

    @staticmethod
    def _marker_rc(text, marker):
        """哨兵结束行里带的退出码；老包装没带就返回 None（None ≠ 0：不许把"没带"当成"成功"）。"""
        end = marker + "end"
        for line in str(text).splitlines():
            line = line.strip()
            if line.startswith(end + " "):
                tail = line[len(end) + 1:].strip().split()[0] if line[len(end) + 1:].strip() else ""
                if tail.isdigit():
                    return int(tail)
        return None

    def _cite(self, events, call_id, quote, stream="stdout", require_marker=False):
        if not isinstance(quote, str) or not quote.strip():
            _error("LEAN_CITATION_INVALID", "a nonempty exact quotation is required")
        if stream not in {"stdout", "stderr"} or type(require_marker) is not bool:
            _error("LEAN_CITATION_INVALID", "only registered stdout/stderr may be quoted")
        intents, receipts = self._calls(events)
        #: **按引文找单据**（爷爷 2026-10-07 口径）：归档是引擎的活，不是模型的活。
        #: 模型只交"原话"；这句原话是哪一发说的，由引擎自己找 —— 它手上有本步全部已核销回执。
        #: 模型给的 `call_id` 只当**提示**：给对了直接用，给错/没给都不会作废（引擎在场自动定位并登记）。
        #: 2026-10-07 walk-72/73 node 12 实测：读回的引文被挂到上一发（`SET`）的 id 上，
        #: 一个归档字段的笔误就毁掉一整格 —— 那是引擎该替它对上的事。
        receipts = {key: value for key, value in receipts.items()
                    if not intents[key].get("parent_call_id")}
        order = [call_id] if call_id in receipts else []
        order += [other for other in receipts if other not in order]
        #: 引文自己也过一遍**同一套脱敏**再比对：回执里存的是脱敏后的文本，模型引的那行却可能
        #: 带着凭据原文（它当时看到的就是原文）—— 不脱敏就永远对不上，把一个"观测明明拿到了"的
        #: 节点判成引文无效（2026-10-07 walk-81 node 7 实测：8 发全 rc=0，结论却卡在引文上）。
        masked_quote = mask_secrets(quote, self.secrets)
        folded_quote = _fold_ws(masked_quote)
        chosen, raw = "", ""
        for candidate in order:
            try:
                text = self._artifact(candidate, stream + ".txt").read_text(encoding="utf-8")
            except OSError:
                continue
            if quote in text or (folded_quote and folded_quote in _fold_ws(text)):
                chosen, raw = candidate, text
                break
        if not chosen:
            #: 报错要**贴题**：模型指名了一条本步根本不存在的调用 → 说"这步没这条调用"，
            #: 比说"没有回执含这句话"清楚得多（也保住隔壁 run 的调用不能被引这条性质）。
            if call_id and call_id not in receipts:
                _error("LEAN_CALL_UNKNOWN", call_id)
            _error("LEAN_CITATION_NOT_FOUND",
                   "no receipt of this step contains that text (%d calls checked)" % len(order))
        if call_id and call_id != chosen:
            #: 留痕：模型报的与引擎定位到的不一致 —— 记下来，不因此作废。
            resolved_from = str(call_id)
        else:
            resolved_from = ""
        receipt = self._verify(chosen, receipts[chosen])
        #: 逐字节子串优先；**空白折叠后的子串也算**（换行/对齐空格的重整不是"编造"）。
        #: 2026-10-06 walk-67 node 14 实测：`nmap -oX -` 的 XML 输出排版一变，模型引用就对不上，
        #: 连吃两次 `LEAN_CITATION_NOT_FOUND` 把节点停了；而它引的确实是那一段原文。
        #: 判定仍然要求"真的出现在这次调用里"，只是不再要求空格/换行逐字符相同。
        if quote in raw:
            offset, matched = raw.index(quote), quote
        else:
            folded_raw = _fold_ws(raw)
            if not folded_quote or folded_quote not in folded_raw:
                #: **当场点名"这句话在哪一发里"**：模型引错单据（把读回的引文挂在上一条的 id 上）时，
                #: 只说"找不到"它下一发还是猜；告诉它正确答案就能一发改对。
                #: 2026-10-07 walk-72/73 node 12 实测：`GET` 的值明明拿到了，模型却把它引到 `SET` 那一发
                #: 的 call_id 上 → 引文核对失败 → 整格作废（一条时序错位毁掉一个节点）。
                _error("LEAN_CITATION_NOT_FOUND", chosen)
            #: 归档里存**脱敏后的那句**（原文只有模型当时看得见）：偏移与留痕都用脱敏版本算，
            #: 免得把凭据又写回账本。
            offset, matched = _raw_offset(raw, masked_quote), masked_quote
        if require_marker:
            stdout = self._artifact(chosen, "stdout.txt").read_text(encoding="utf-8")
            if not self._marked(stdout, intents[chosen]["marker"]):
                _error("LEAN_MARKER_MISSING", chosen)
        return {"status": "checked", "call_id": chosen, "stream": stream, "quote": matched,
                "offset": offset, "artifact_sha256": receipt["artifacts"][stream + ".txt"]["sha256"],
                "require_marker": require_marker,
                #: 模型报的 id 与引擎定位到的不一致时记在这里（归档留痕，不作废）。
                "resolved_from": resolved_from,
                "meaning": "quotation_exists_only"}

    def cite(self, call_id, quote, stream="stdout", require_marker=False):
        with ownership(self.root):
            return self._cite(self._read(), call_id, quote, stream, require_marker)

    def citation_index(self):
        """What may be quoted right now: one row per registered call, with its marker state.

        A refusal has to be actionable. "Your quotation was not found" tells the model nothing
        about *where* to look, so the correction turn gets the list of calls the run really made
        and whether each one carries a complete wrapper marker - the two facts a citation
        depends on, both of which the engine already knows.
        """
        with ownership(self.root):
            events = self._read()
            intents, receipts = self._calls(events)
            rows = []
            for call_id in intents:
                if intents[call_id].get("parent_call_id"):
                    continue
                receipt = receipts.get(call_id)
                if receipt is None:
                    continue
                marked = False
                stdout, stderr = "", ""
                try:
                    view = self._view(receipt)
                    stdout, stderr = view["stdout"], view["stderr"]
                    marked = self._marked(stdout, intents[call_id]["marker"])
                except (OSError, KeyError):
                    marked = False
                rows.append({"call_id": call_id, "status": receipt.get("status"),
                             #: **把原文片段一起给出去**：只说"哪几发能引"是不够的 —— 模型下一发要么
                             #: 继续凭记忆重构，要么干脆编一句像样的（2026-10-07 walk-84 node 7 实测：
                             #: 它编了一条登录响应 `{"status":1,…}`，六份回执里一个字都没有）。
                             #: 给它一眼能抄的原文（脱敏后、截短），它才有机会照抄。
                             "excerpt": self._safe(" ".join(stdout.split())[:160]),
                             "marker_complete": marked,
                             "streams": {name: {"chars": len(text), "head": text[:320],
                                               "tail": text[-320:] if len(text) > 320 else "",
                                               "tail_start": max(0, len(text) - 320)}
                                         for name, text in (("stdout", stdout), ("stderr", stderr))}})
            return rows

    def request_correction(self, feedback):
        """Ask for a corrected conclusion, once, with the refusal and the legal range attached.

        A quotation that names the wrong call is a bookkeeping mistake, not a failed step - the
        observation is already on disk. The request is written as its own event so the model sees
        *why* it is being asked again, and the runtime refuses to run anything in that turn (see
        ``drive``): "only the claim and the citations may change" has to be enforced, not stated.
        """
        with ownership(self.root):
            return self._append("correction", feedback=self._safe(feedback))

    def check_materials(self, materials):
        """Validate model inference against a completed current call before registration."""
        if not self.card.get("materials"):
            #: 卡没声明 materials、模型却带了一份：**忽略并留痕，不许把节点杀掉**。
            #: 2026-10-06 walk-66 node 2 实测：那一步真的把 DC 防火墙关掉了（回读里 `状态 关闭` 就摆着），
            #: 只因为模型顺手把刚用过的域管凭据又复述了一遍，整节点以 `LEAN_MATERIALS_UNDECLARED` 停住，
            #: 成果没能记账、44 因此派不出来。多给材料是"复述手头的东西"，不是目标结果，不该是致命错误。
            if materials:
                self.ignored_materials = True
            return []
        #: **没给材料 ≠ 材料不合法**：卡声明 materials 时，结论不是 pass 的回合本来就不该交材料
        #: （"这一步没有观测到"就该如实说）。只有结论要 pass 时才必须交（那是 LEAN_MATERIALS_MISSING）。
        #: 2026-10-06 walk-63 node 5 实测：模型诚实写下"三次回包只有传输标记、没有任何凭据行"，
        #: 却吃到 LEAN_MATERIALS_INVALID —— 节点停住，而且这个错误名把责任指给了模型。
        if materials is None:
            return []
        if not isinstance(materials, list):
            _error("LEAN_MATERIALS_INVALID")
        _intents, receipts = self._calls(self._read())
        checked = []
        required = {"realm", "user", "value", "kind", "source_call", "quote"}
        for material in materials:
            if (not isinstance(material, dict) or not required <= material.keys()
                    or set(material) - required - {"stream"}
                    or any(not isinstance(material[key], str) for key in required)
                    or material["kind"] not in {"password", "ntlm"}
                    or not material["user"].strip() or not material["value"]
                    or not material["quote"].strip()):
                _error("LEAN_MATERIAL_INVALID")
            call_id, stream = material["source_call"], material.get("stream", "stdout")
            if stream not in {"stdout", "stderr"}:
                _error("LEAN_MATERIAL_INVALID")
            receipt = receipts.get(call_id)
            if receipt is None or receipt.get("status") != "completed_transport":
                _error("LEAN_MATERIAL_CALL_UNCONFIRMED")
            self._verify(call_id, receipt)
            raw = self.observations.get(call_id)
            if raw is None:
                _error("LEAN_MATERIAL_SOURCE_UNAVAILABLE")
            quote = material["quote"]
            if quote not in raw[stream] or any(value and value not in quote for value in
                    (material["realm"], material["user"], material["value"])):
                _error("LEAN_MATERIAL_QUOTE_MISMATCH")
            if material["value"] not in self.secrets:
                _error("LEAN_MATERIAL_VALUE_UNDECLARED")
            checked.append(dict(material))
        return checked

    def delivery_needles(self) -> list:
        """What this step must send before its declared hand-over counts as run.

        Every group is a requirement, and a requirement is met when **any** of its alternatives
        shows up in what the step sent. A hand-over has two halves and both are required: the
        payload is planted (the plant command the run handed over - it *is* the artefact, so a
        request carrying it is that request being run), and the stager is started. The second half
        is evidenced either by the run's own trigger string (`delivery_command`) or by the
        stager's file name - the name is the older signal, and it is what covers hand-overs whose
        command is sent in pieces (a `scp` and then an `ssh`, each its own action). Checking only
        the planting let a step that had planted and never started anything conclude as
        "unsatisfied" and end the node, with everything downstream waiting on its product
        (measured 2026-10-08, walk-175 node 7: login verified, the upload and the include never
        sent, and the gate stayed quiet).
        """
        inputs = self.task.get("inputs") or {}
        groups = []
        plant = str(inputs.get("delivery_plant_command") or "").strip()
        if plant:
            groups.append([plant])
        started = []
        trigger = str(inputs.get("delivery_command") or "").strip()
        if trigger:
            started.append(trigger)
        names = []
        values = [str(inputs.get("delivery_remote_stager") or "")]
        values.extend(str(inputs.get("delivery_command") or "").split())
        for value in values:
            name = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
            if name.endswith((".bin", ".exe")):
                names.append(name)
        started.extend(names)
        if started:
            groups.append(list(dict.fromkeys(started)))
        return groups

    def delivery_pending(self) -> bool:
        """Whether the declared hand-over still has to be run before this step may conclude.

        A node that declares a session is not finished by a command echo: it was handed the one
        line that plants and starts the stager, and answering before running it loses the session
        (measured 2026-10-08, walk-135 node 12: the model wrote the ssh key, concluded, and the
        run waited for a callback nobody had asked for).

        Needles are matched the way the rest of the runtime matches text: folded, not raw. A
        base64 plant command never shows the stager's name in the clear, so a name-only check
        read a verbatim copy of the handed command as "delivery not issued" and threw away a
        step whose chain had already run (measured 2026-10-08, walk-172 node 19: the request
        and `delivery_plant_command` were the same 529 characters, and the step was still
        refused three times).
        """
        groups = self.delivery_needles()
        if not groups:
            return False
        from urllib.parse import unquote_plus

        intents, _ = self._calls(self._read())
        #: Percent-encoding is presentation, not content: the trigger travels inside a request path
        #: as `echo%20AGV_DELIVERY_TRIGGER` (or `echo+AGV_DELIVERY_TRIGGER`), so comparing the raw
        #: JSON would read a hand-over that was run as one that never was. Both sides of the
        #: comparison get the same treatment, so this cannot invent a match.
        seen = [_fold_ws(unquote_plus(json.dumps(row.get("request") or {}, ensure_ascii=False)))
                for row in intents.values()]
        for group in groups:
            wanted = [_fold_ws(unquote_plus(needle)) for needle in group if str(needle).strip()]
            if not any(needle in text for text in seen for needle in wanted):
                return True
        return False

    def conclude(self, claim, citations, claimed_verdict="uncertain", materials=None):
        dispatch.require_declared(self.card, "finish")
        with ownership(self.root):
            events = self._read()
            pending = self._pending(events)
            materials = self.check_materials(materials)
            if self.card.get("materials") and claimed_verdict == "pass" and not materials:
                _error("LEAN_MATERIALS_MISSING")
            checked, rejected = [], []
            if not isinstance(claim, str) or not claim.strip() or not isinstance(citations, list):
                _error("LEAN_CLAIM_INVALID", "claim text and citation list are required")
            for citation in citations:
                try:
                    if not isinstance(citation, dict):
                        _error("LEAN_CITATION_INVALID", "citation must be an object")
                    # A model's checked=true or artifact path is never an authorization to trust it.
                    checked.append(self._cite(events, citation.get("call_id"), self._safe(citation.get("quote")),
                                              citation.get("stream", "stdout"), citation.get("require_marker", False)))
                except (ValueError, TypeError) as error:
                    rejected.append(self._safe(str(error)))
            status = "uncertain" if pending or rejected else "model_reported"
            result = {"status": status, "claimed_verdict": claimed_verdict,
                      "claim": self._safe(claim), "citations": checked, "rejections": rejected,
                      "pending_calls": pending, "machine_verified": False,
                      "reason": "LEAN_UNRESOLVED_CALL" if pending else "LEAN_CITATION_INVALID"
                      if rejected else "MODEL_CLAIM_NOT_MACHINE_VERIFIED"}
            if materials:
                result["materials"] = materials
            elif self.ignored_materials:
                #: 留痕：模型给过材料、但这张卡没声明 —— 忽略了，不是没看见。
                result["materials_ignored"] = "card declares no materials"
            self._append("conclusion", result=mask_secrets(result, self.secrets))
            return result
