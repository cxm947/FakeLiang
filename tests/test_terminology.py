'''Terminology guard: the current contract speaks "skill", not the v3 "ability" vocabulary.

docs/product/glossary.md is the single source for the domain words. This test keeps the
machine surfaces and the current contract pages from drifting back to the retired ones.
History is preserved on purpose: archive/, docs/decisions.md and docs/product/reference/ may
quote the old words, and every *current* page that does has to say so. The current-page
scan is recursive and fail-closed (every markdown page under docs/, data/samples/ and
specs/, plus the constitution AGENTS.md), so a
page is guarded the day it lands instead of the day someone remembers to list it; the
exemptions are one short, visible list and each of them has to declare itself history.

Two rules, one per language the contract is written in:

* English: "ability"/"abilities" as standalone words, plus the phrase "capability gap".
  "capabilities" in the Linux sense (the kernel capability set a container escape depends on)
  is a different domain word and stays allowed.
* Chinese: 「能力」 is an ordinary word (执行能力 / 攻击能力 / 身份和能力). It is retired only where
  it names the registry unit -- 「能力注册表」「能力卡」「一条能力」 all have to be 「技能」.
  Retired are the unit-noun compounds and the counted forms below, not the general word.
'''

import json
import re
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from tests.support import ROOT

#: ability / abilities as standalone words.
RETIRED = re.compile(r'(?<![A-Za-z])abilit(?:y|ies)(?![A-Za-z])')
RETIRED_PHRASE = re.compile(r'capabilit(?:y|ies)\s+gap', re.IGNORECASE)
#: 「能力」当作注册单元：只有技能才有的单位名词。
RETIRED_CN_NOUN = re.compile('能力(?:注册表|卡片|卡|检索|缺口|目录|索引|池|清单|选择|适配器|条目|记录|编排)')
#: 把「能力」当成可数个体数的写法（一条/本/该/新增…能力）。
RETIRED_CN_UNIT = re.compile(
    '(?:一条|每条|一项|每项|这项|这条|单条|一个|本|该|新增|注册|已注册|候选|锁定|现有|已有|预置)能力')
#: 四条规则一起用；命中清单按声明顺序返回，报错时能直接看出踩了哪条。
RETIRED_ANY = (RETIRED, RETIRED_PHRASE, RETIRED_CN_NOUN, RETIRED_CN_UNIT)
HISTORY_MARKERS = ('旧', '历史', '归档', '退役', 'v3', '术语', 'legacy', 'archive', 'deprecated')

#: Where a page may name the retired words: it is history, and it has to say so (see the
#: test below). decisions.md narrates the rename; reference/ keeps the frozen v0.1 / v0.2
#: PRD baselines; archive/ is the pre-v3 draft tree.
HISTORY_SURFACES = ('docs/decisions.md', 'docs/product/reference', 'archive')
#: The roots whose markdown pages describe *this* version - scanned recursively.
CURRENT_DOC_DIRS = ('docs', 'data/samples', 'specs')
MACHINE_DIRS = ('src', 'scripts', 'schemas', 'tests')
MACHINE_FILES = ('README.md', 'scripts/README.md', 'AGENTS.md')
SKIP_PARTS = ('.venv', 'output', 'tmp', '__pycache__')
#: This guard has to name the retired words to forbid them, so it is the one machine surface
#: that is allowed to spell them out.
SKIP_FILES = ('tests/test_terminology.py',)
SCAN_SUFFIXES = ('.py', '.json', '.md', '.yaml')

GLOSSARY = ROOT / 'docs/product/glossary.md'
#: Every word the contract relies on has to be defined somewhere a reader can find.
CANONICAL = ('skill', 'skill id', 'registry', 'index', 'card', 'knowledge', 'adapter',
             'case', 'provides', 'status', 'selection', 'binding', 'missing',
             'pending', 'attempt', 'call', 'envelope', 'judgement', 'gate', 'node', 'run',
             'need', 'supply', 'assumption', 'graph_gap', 'skill_gap')


def machine_files():
    '''Code, schemas, cards and the entry-point readmes: the surfaces a machine reads.'''
    for name in MACHINE_FILES:
        yield ROOT / name
    for folder in MACHINE_DIRS:
        for path in sorted((ROOT / folder).rglob('*')):
            if path.is_file() and path.suffix in SCAN_SUFFIXES:
                yield path
    # Package prompts remain machine surfaces after moving out of Python.
    for folder in ('src/agents/_model/templates', 'src/agents/planner/templates',
                   'src/agents/executor/templates',
                   'src/agents/verifier/templates', 'src/skills/templates'):
        for path in sorted((ROOT / folder).glob('*.txt')):
            if path.is_file():
                yield path
    # 技能卡两面都要干净：机器契约 skill.json 与知识卡 SKILL.md。
    for path in sorted((ROOT / 'skills').rglob('*')):
        if path.is_file() and path.suffix in ('.json', '.md'):
            yield path


def is_history_surface(path: Path) -> bool:
    '''A declared history surface: it may quote the retired words, and it says so itself.'''
    relative = str(path.relative_to(ROOT)).replace('\\', '/')
    return any(relative == surface or relative.startswith(surface + '/')
               for surface in HISTORY_SURFACES)


def current_contract_docs():
    '''Every markdown page that describes *this* version, minus the declared history surfaces.

    Recursive on purpose (fail-closed): a page added under docs/ or data/samples/ is guarded
    the moment it lands. The exemptions are the short list above, and each one has to
    declare itself history - HistorySurfaceTests checks that out loud.
    '''
    for folder in CURRENT_DOC_DIRS:
        for path in sorted((ROOT / folder).rglob('*.md')):
            if not is_history_surface(path):
                yield path


def is_skipped(path: Path) -> bool:
    if any(part in path.parts for part in SKIP_PARTS):
        return True
    relative = str(path.relative_to(ROOT)).replace('\\', '/')
    return relative in SKIP_FILES


def retired_hits(text: str) -> list:
    '''Every retired form in one text, in the order the rules are declared.'''
    return [match.group(0) for rule in RETIRED_ANY for match in rule.finditer(text)]


def current_doc_scan_text(path: Path, text: str) -> str:
    '''Mask only existing history paths in the file-tree JSON inventory.'''
    if path != ROOT / 'docs/file_tree.md':
        return text
    start = '<!-- agv:file-list:start -->'
    end = '<!-- agv:file-list:end -->'
    if text.count(start) != 1 or text.count(end) != 1:
        return text
    before, _, rest = text.partition(start)
    block, _, after = rest.partition(end)
    fenced = re.fullmatch(
        r'\s*```json[ \t]*\n(?P<body>.*?)\n```[ \t]*\s*', block, re.DOTALL)
    if fenced is None:
        return text
    body = fenced.group('body')
    try:
        entries = json.loads(body)
    except ValueError:
        return text
    if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
        return text

    def mask_history(token):
        value = json.loads(token.group(0))
        relative = PurePosixPath(value)
        if (relative.is_absolute() or value != relative.as_posix()
                or '..' in relative.parts or '\\' in value):
            return token.group(0)
        try:
            target = ROOT / value
            if not is_history_surface(target) or not target.is_file():
                return token.group(0)
        except (OSError, ValueError):
            return token.group(0)
        return ' ' * len(token.group(0))

    masked = re.sub(r'"(?:[^"\\]|\\.)*"', mask_history, body)
    block = block[:fenced.start('body')] + masked + block[fenced.end('body'):]
    return before + start + block + end + after


class MachineSurfaceTests(unittest.TestCase):
    def test_machine_surfaces_do_not_use_the_retired_words(self):
        for path in machine_files():
            if is_skipped(path):
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertEqual([], retired_hits(text), 'retired wording in a machine surface')


class ContractDocTests(unittest.TestCase):
    def test_current_pages_only_mention_history_out_loud(self):
        for path in current_contract_docs():
            if is_skipped(path):
                continue
            text = current_doc_scan_text(path, path.read_text(encoding='utf-8'))
            for number, line in enumerate(text.splitlines(), 1):
                if not retired_hits(line):
                    continue
                with self.subTest(path=str(path.relative_to(ROOT)), line=number):
                    self.assertTrue(any(marker in line for marker in HISTORY_MARKERS),
                                    'a current page quoting a retired word must mark it as history')

    def test_no_current_document_is_named_after_the_retired_nouns(self):
        # 仓库根的散落 md 也在里面：D33 就抓到一个 3 字节的根级文件，名字还带着退役词。
        documents = sorted(ROOT.glob('*.md'))
        for folder in CURRENT_DOC_DIRS:
            documents += sorted((ROOT / folder).rglob('*.md'))
        for path in documents:
            if is_skipped(path) or is_history_surface(path):
                continue
            name = path.name.lower()
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertNotIn('ability', name)
                self.assertNotIn('capability', name)


class InventoryHistoryReferenceTests(unittest.TestCase):
    def test_inventory_exemption_is_limited_to_history_path_tokens(self):
        page = ROOT / 'docs/file_tree.md'
        history = [
            'docs/product/reference/v0.1-detailed/ability_skill_matcher_prd.md',
            'docs/product/reference/v0.2-detailed/ability_skill_matcher_prd.md',
        ]

        def inventory(body):
            return ('<!-- agv:file-list:start -->\n```json\n' + body
                    + '\n```\n<!-- agv:file-list:end -->\n')

        valid = inventory(json.dumps(history, indent=2))
        cases = [
            ('history entries', page, valid, True),
            ('current path', page, inventory('["src/ability.py"]'), False),
            ('same-line mixed paths', page,
             inventory(json.dumps([history[0], 'src/ability.py'])), False),
            ('prose outside inventory', page, valid + 'ability\n', False),
            ('history path outside inventory', page, json.dumps(history[0]), False),
            ('another current page', ROOT / 'docs/product/README.md', valid, False),
            ('invalid JSON', page, inventory('[' + json.dumps(history[0]) + ',]'), False),
            ('wrong JSON shape', page, inventory(json.dumps({'path': history[0]})), False),
            ('missing end marker', page,
             valid.replace('<!-- agv:file-list:end -->', ''), False),
            ('duplicate inventory', page, valid + valid, False),
            ('lookalike history prefix', page,
             inventory('["docs/product/reference-copy/ability.md"]'), False),
            ('parent traversal', page,
             inventory('["docs/product/reference/../../ability.md"]'), False),
            ('missing history file', page,
             inventory('["docs/product/reference/__missing_s3_ability__.md"]'), False),
            ('same-line history marker', page, '历史 ability\n', True),
            ('nearby history marker', page, '历史\nability\n', False),
        ]
        for name, document, text, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(text.count('\n'), current_doc_scan_text(document, text).count('\n'))
                result = unittest.TestResult()
                with patch(__name__ + '.current_contract_docs', return_value=[document]), \
                        patch.object(Path, 'read_text', return_value=text):
                    ContractDocTests('test_current_pages_only_mention_history_out_loud').run(result)
                self.assertFalse(result.errors, result.errors)
                self.assertEqual(expected, result.wasSuccessful(), result.failures)


class GlossaryTests(unittest.TestCase):
    def test_glossary_defines_every_domain_word(self):
        text = GLOSSARY.read_text(encoding='utf-8')
        missing = [word for word in CANONICAL if word not in text]
        self.assertEqual([], missing, 'the glossary has to define these words')

    def test_glossary_retires_the_old_nouns_and_says_where_history_lives(self):
        text = GLOSSARY.read_text(encoding='utf-8')
        self.assertIn('ability', text)
        self.assertIn('archive/legacy_v3_ability', text)

    def test_glossary_retires_the_chinese_unit_noun_too(self):
        text = GLOSSARY.read_text(encoding='utf-8')
        self.assertIn('能力', text)
        self.assertIn('技能检索', text)


def history_surface_readmes():
    '''One README per declared history surface: the page that has to say "this is history".'''
    return sorted([ROOT / 'archive' / 'README.md']
                  + list((ROOT / 'docs' / 'product' / 'reference').glob('*/README.md')))


class HistorySurfaceTests(unittest.TestCase):
    def test_declared_history_surfaces_exist(self):
        '''A surface that stops existing must not stay in the exemption list by accident.'''
        for surface in HISTORY_SURFACES:
            with self.subTest(surface=surface):
                self.assertTrue((ROOT / surface).exists(),
                                'a declared history surface has to exist')

    def test_history_surfaces_declare_themselves_as_history(self):
        '''An exempted surface stays out of the guard only while it says it is history.'''
        readmes = history_surface_readmes()
        self.assertTrue(readmes, 'the history surfaces keep a README that declares them history')
        for path in readmes:
            text = path.read_text(encoding='utf-8')
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertTrue(any(marker in text for marker in HISTORY_MARKERS),
                                'a history surface README has to say it is history')


if __name__ == '__main__':
    unittest.main()
