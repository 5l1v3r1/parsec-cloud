import re
import attr
from functools import wraps
from hypothesis.stateful import (
    RuleBasedStateMachine,
    rule as vanilla_rule,
    precondition,
    VarReference,
)
from huepy import red, bold


def rule(**config):
    def dec(fn):
        @vanilla_rule(**config)
        @wraps(fn)
        def wrapper(*args, **kwargs):
            print(red(bold("%s(%s)" % (fn.__name__, kwargs))))
            try:
                return fn(*args, **kwargs)

            except AssertionError as exc:
                import tests.hypothesis.test_core_online_tree_and_sync

                # import pdb; pdb.set_trace()
                raise

        return wrapper

    return dec


def rule_once(*args, **kwargs):
    def accept(f):
        key = "__%s_hypothesis_initialized" % f.__name__

        def bootstrap(obj):
            if not getattr(obj, key, False):
                setattr(obj, key, True)
                return True

            else:
                return False

        return precondition(bootstrap)(rule(*args, **kwargs)(f))

    return accept


class FileOracle:
    def __init__(self):
        self._buffer = bytearray()

    def read(self, size, offset):
        return self._buffer[offset : size + offset]

    def write(self, offset, content):
        if not content:
            return
        gap = offset - len(self._buffer)
        if gap > 0:
            self._buffer += bytearray(gap)
        self._buffer[offset : len(content) + offset] = content

    def truncate(self, length):
        new_buffer = bytearray(length)
        copy_size = min(length, len(self._buffer))
        new_buffer[:copy_size] = self._buffer[:copy_size]
        self._buffer = new_buffer


@attr.s
class OracleFSFile:
    need_sync = attr.ib(default=True)
    need_flush = attr.ib(default=False)
    base_version = attr.ib(default=0)

    @property
    def is_placeholder(self):
        return self.base_version == 0


@attr.s(repr=False)
class OracleFSFolder(dict):
    need_sync = attr.ib(default=True)
    need_flush = attr.ib(default=False)
    base_version = attr.ib(default=0)

    def __repr__(self):
        children = {k: v for k, v in self.items()}
        return (
            "{type}("
            "need_sync={self.need_sync}, "
            "need_flush={self.need_flush}, "
            "base_version={self.base_version}, "
            "children={children})"
        ).format(type=type(self).__name__, self=self, children=children)

    @property
    def is_placeholder(self):
        return self.base_version == 0


@attr.s(repr=False)
class OracleFSRootFolder(OracleFSFolder):
    @property
    def is_placeholder(self):
        return False


def normalize_path(path):
    return "/" + "/".join([x for x in path.split("/") if x])


@attr.s
class OracleFS:
    root = attr.ib(factory=OracleFSRootFolder)

    def create_file(self, path):
        path = normalize_path(path)
        parent_path, name = path.rsplit("/", 1)

        parent_dir = self.get_folder(parent_path)
        if parent_dir is None or name in parent_dir:
            return "invalid_path"

        parent_dir[name] = OracleFSFile()
        parent_dir.need_sync = True
        return "ok"

    def create_folder(self, path):
        path = normalize_path(path)
        parent_path, name = path.rsplit("/", 1)

        parent_dir = self.get_folder(parent_path)
        if parent_dir is None or name in parent_dir:
            return "invalid_path"

        parent_dir[name] = OracleFSFolder()
        parent_dir.need_sync = True
        return "ok"

    def delete(self, path):
        path = normalize_path(path)
        if path == "/":
            return "invalid_path"

        parent_path, name = path.rsplit("/", 1)
        parent_dir = self.get_path(parent_path or "/")
        if isinstance(parent_dir, OracleFSFolder) and name in parent_dir:
            item = parent_dir[name]
            if isinstance(item, OracleFSFolder) and len(item):
                return "invalid_path"

            del parent_dir[name]
            parent_dir.need_sync = True
            return "ok"

        else:
            return "invalid_path"

    def move(self, src, dst):
        src = normalize_path(src)
        dst = normalize_path(dst)

        if src == dst:
            return "ok"

        if src == "/" or dst == "/":
            return "invalid_path"

        if dst.startswith(src + "/"):
            return "invalid_path"

        parent_src, name_src = src.rsplit("/", 1)
        parent_dst, name_dst = dst.rsplit("/", 1)

        parent_dir_src = self.get_folder(parent_src)
        parent_dir_dst = self.get_folder(parent_dst)

        if parent_dir_src is None or name_src not in parent_dir_src:
            return "invalid_path"

        if parent_dir_dst is None:
            return "invalid_path"

        dst_as_folder = self.get_folder(dst)
        if dst_as_folder is not None and dst_as_folder:
            # Not empty folder
            return "invalid_path"

        parent_dir_dst[name_dst] = parent_dir_src.pop(name_src)
        parent_dir_dst.need_sync = True
        parent_dir_src.need_sync = True
        return "ok"

    def get_folder(self, path):
        path = normalize_path(path)

        elem = self.get_path(path)
        return elem if isinstance(elem, OracleFSFolder) else None

    def get_file(self, path):
        path = normalize_path(path)

        elem = self.get_path(path)
        return elem if isinstance(elem, OracleFSFile) else None

    def get_path(self, path):
        path = normalize_path(path)

        current_entry = self.root
        try:
            for item in path.split("/"):
                if item:
                    current_entry = current_entry[item]
        except (KeyError, TypeError):
            # Next entry is not in folder or we reached a file instead of a folder
            return None

        return current_entry

    def flush(self, path):
        entry = self.get_path(path)
        if entry is not None:
            entry.need_flush = False
            return "ok"
        return "invalid_path"

    def sync(self, path):
        entry = self.get_path(path)
        if entry is not None:
            self._backward_recursive_sync(path)
            self._recursive_children_sync(entry)
            return "ok"
        return "invalid_path"

    def _recursive_children_sync(self, entry):
        if isinstance(entry, OracleFSFolder):
            for child_entry in entry.values():
                if child_entry.need_sync:
                    child_entry.need_flush = False
                    child_entry.need_sync = False
                    child_entry.base_version += 1
                self._recursive_children_sync(child_entry)

    def _backward_recursive_sync(self, path):
        curr_path = path
        child_asked_for_sync = None
        while True:
            entry = self.get_path(curr_path)
            entry_was_placeholder = entry.is_placeholder
            if child_asked_for_sync:
                entry.base_version += 1
                entry.need_flush = False
                entry.need_sync = entry.keys() != {child_asked_for_sync}
            elif entry.need_sync:
                entry.need_flush = False
                entry.need_sync = False
                entry.base_version += 1
            else:
                break

            if entry_was_placeholder:
                curr_path, name = curr_path.rsplit("/", 1)
                child_asked_for_sync = name
            else:
                break

    def stat(self, path):
        entry = self.get_path(path)
        if entry is not None:
            return {
                "status": "ok",
                "base_version": entry.base_version,
                "is_placeholder": entry.is_placeholder,
                "need_flush": entry.need_flush,
                "need_sync": entry.need_sync,
            }
        else:
            return {"status": "invalid_path"}


class BaseFailureReproducer:

    _FAILURE_REPRODUCER_CODE_HEADER = """import pytest


@pytest.mark.trio
async def test_reproduce(alice_core_sock, alice2_core2_sock):
"""

    def teardown(self):
        super().teardown()
        if hasattr(self, "_failure_reproducer_code"):
            print("============================ REPRODUCE CODE ========================")
            print(
                self._failure_reproducer_template.format(
                    body="\n".join(self._failure_reproducer_code).strip()
                )
            )
            print("====================================================================")

    def print_step(self, step):
        super().print_step(step)

        if not hasattr(self, "_failure_reproducer_code"):
            assert "{body}" in self._FAILURE_REPRODUCER_CODE_HEADER
            self._failure_reproducer_template = self._FAILURE_REPRODUCER_CODE_HEADER
            self._failure_reproducer_code = []
            match = re.search(
                r"^( *)\{body\}", self._failure_reproducer_template, flags=re.MULTILINE
            )
            self._failure_reproducer_indent = match.group(1)

        def indent(code):
            if not isinstance(code, list):
                code = code.strip().split("\n")
            return [self._failure_reproducer_indent + x for x in code]

        rule, data = step
        template = getattr(rule.function, "_reproduce_template", None)
        rule_brief = "%s(%r)" % (rule.function.__name__, data)
        if not template:
            self._failure_reproducer_code += indent("# Nothing to do for rule %s" % rule_brief)
            return
        else:
            self._failure_reproducer_code.append("")
            self._failure_reproducer_code += indent("# Rule %s" % rule_brief)

        resolved_data = {}
        for k, v in data.items():
            if isinstance(v, VarReference):
                resolved_data[k] = repr(self.names_to_values[v.name])
            else:
                resolved_data[k] = repr(v)

        code = template.format(**resolved_data)
        self._failure_reproducer_code += indent(code)


def failure_reproducer(init=BaseFailureReproducer._FAILURE_REPRODUCER_CODE_HEADER):
    def wrapper(cls):
        assert issubclass(cls, RuleBasedStateMachine)
        nmspc = {"_FAILURE_REPRODUCER_CODE_HEADER": init}
        return type("%sWithFailureReproducer" % cls.__name__, (BaseFailureReproducer, cls), nmspc)

    return wrapper


def reproduce_rule(template):
    def wrapper(fn):
        fn._reproduce_template = template
        return fn

    return wrapper
