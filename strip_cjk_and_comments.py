import sys
import io
import ast
import re
import tokenize


def collect_docstring_spans(source_text: str):
    """Return a list of ((lineno, col), (end_lineno, end_col)) docstring spans."""
    spans = []
    try:
        module = ast.parse(source_text)
    except Exception:
        return spans

    def record(node):
        if not getattr(node, "body", None):
            return
        first = node.body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            ln = getattr(first, "lineno", None)
            eln = getattr(first, "end_lineno", ln)
            col = getattr(first, "col_offset", 0)
            ecol = getattr(first, "end_col_offset", 0)
            if ln is not None:
                spans.append(((ln, col), (eln, ecol)))

    record(module)
    for n in ast.walk(module):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            record(n)
    return spans


def position_in_spans(pos, spans):
    (l, c) = pos
    for (sl, sc), (el, ec) in spans:
        if (l > sl or (l == sl and c >= sc)) and (l < el or (l == el and c <= ec)):
            return True
    return False


def strip_file(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    # Collect docstring positions first (before tokenization rewrites positions)
    docstring_spans = collect_docstring_spans(src)

    # Regex to strip CJK (Chinese) characters and common CJK punctuation/fullwidth forms
    cjk_re = re.compile(r"[\u4E00-\u9FFF\u3400-\u4DBF\u3000-\u303F\uFF00-\uFFEF]+")

    out_tokens = []
    reader = io.StringIO(src).readline
    for tok in tokenize.generate_tokens(reader):
        tok_type, tok_str, start, end, line = tok
        if tok_type == tokenize.COMMENT:
            # Drop comments entirely
            continue
        if tok_type == tokenize.STRING:
            # Remove docstrings entirely
            if position_in_spans(start, docstring_spans):
                continue
            # Sanitize string literal content by removing CJK characters
            try:
                val = ast.literal_eval(tok_str)
                if isinstance(val, str):
                    new_val = cjk_re.sub('', val)
                    tok_str = repr(new_val)
            except Exception:
                # For f-strings/others, fallback to direct regex on token text
                tok_str = cjk_re.sub('', tok_str)
            out_tokens.append((tok_type, tok_str))
            continue
        out_tokens.append((tok_type, tok_str))

    new_src = tokenize.untokenize(out_tokens)

    # Final safeguard: remove any remaining CJK characters that might be outside literals
    new_src = cjk_re.sub('', new_src)

    with open(path, "w", encoding="utf-8") as f:
        f.write(new_src)


def main():
    if len(sys.argv) != 2:
        print("Usage: python strip_cjk_and_comments.py <path_to_python_file>")
        sys.exit(1)
    target = sys.argv[1]
    strip_file(target)


if __name__ == "__main__":
    main()


