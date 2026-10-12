import unittest

from graph.parser import GraphFormatError, digest, read_text
from graph.terms import atom_value, parse_fact, term_key


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.text = '1,"execCode(host,admin)","OR",0\n2,"RULE 7 (demo)","AND",0\n3,"hacl(a,host,tcp,80)","LEAF",1\n2,3,-1\n1,2,-1\n'

    def test_csv_direction_and_fields(self):
        graph = read_text(self.text)
        self.assertEqual(graph.parents["2"], {"3"})
        self.assertEqual(graph.children["2"], {"1"})
        self.assertEqual(graph.nodes["3"].metric, "1")
        self.assertEqual(graph.weights["3", "2"], "-1")

    def test_bom_and_blank_lines(self):
        self.assertEqual(len(read_text("\ufeff\n" + self.text).nodes), 3)

    def test_explicit_reverse_dialect(self):
        reverse = self.text.replace("2,3,-1", "3,2,-1").replace("1,2,-1", "2,1,-1")
        self.assertEqual(read_text(reverse, edge_order="source-target").archive(), read_text(self.text).archive())
        with self.assertRaises(GraphFormatError):
            read_text(reverse)

    def test_duplicate_id_including_leading_zero(self):
        with self.assertRaises(GraphFormatError):
            read_text(self.text + '02,"duplicate","AND",0\n')

    def test_dangling_edge(self):
        with self.assertRaises(GraphFormatError):
            read_text(self.text + "2,99,-1\n")

    def test_duplicate_edge_warning_and_conflict(self):
        graph = read_text(self.text + "2,3,-1\n")
        self.assertEqual(len(graph.weights), 2)
        self.assertEqual(graph.diagnostics[0]["code"], "duplicate_edge")
        with self.assertRaises(GraphFormatError):
            read_text(self.text + "2,3,0\n")

    def test_malformed_rows(self):
        for text in ["", "1,2\n", '1,"unterminated\n', self.text.replace('"AND"', '"XOR"'), self.text + "x,2,-1\n", self.text + "1,3,nan\n"]:
            with self.subTest(text=text), self.assertRaises(GraphFormatError):
                read_text(text)

    def test_fact_quote_nesting_and_windows_paths(self):
        fact = parse_fact(r"example('a,b',nested(x,y),[a,b],'C:\lab\path', 'it''s')")
        self.assertEqual(len(fact.args), 5)
        self.assertEqual(atom_value(fact.args[0]), "a,b")
        self.assertEqual(atom_value(fact.args[4]), "it's")
        self.assertEqual(atom_value(fact.args[3]), "C:\\lab\\path")

    def test_invalid_fact_balancing(self):
        for text in ["x(a,,b)", "x([a))", "x('broken)", "x(a,)"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_fact(text)

    def test_numeric_atom_distinction(self):
        self.assertNotEqual(term_key("2049"), term_key("'2049'"))
        self.assertEqual(term_key("admin"), term_key("'admin'"))
        self.assertNotEqual(term_key("123456789012345678901234567891"), term_key("123456789012345678901234567892"))

    def test_unknown_fact_kept_as_raw(self):
        graph = read_text(self.text.replace("hacl(a,host,tcp,80)", "opaque condition"))
        self.assertEqual(graph.nodes["3"].description, "opaque condition")
        self.assertEqual(graph.diagnostics[0]["code"], "unparsed_fact")

    def test_canonical_graph_ignores_record_order(self):
        a = read_text(self.text)
        b = read_text("\n".join(reversed(self.text.splitlines())))
        self.assertEqual(digest(a.archive()), digest(b.archive()))


if __name__ == "__main__":
    unittest.main()
