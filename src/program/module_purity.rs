//! Load-time recognition of PyCL module bodies that can be run once and
//! snapshotted instead of being run for every connection.
//!
//! A censor script's module body normally runs once per connection, in that
//! connection's own globals. If the body is *pure* — its result depends on
//! nothing but the script itself and it has no effect outside the globals it
//! builds — then running it once and giving every connection a copy of the
//! result is indistinguishable from running it again. This module decides,
//! on the syntax tree, whether a body is pure, using a deliberately small,
//! explicit grammar; anything outside it makes the script ineligible (and it
//! keeps running the body per connection). The values the body produces are
//! checked separately, at runtime (see `crate::transport`).
//!
//! The body runs with `packet`, `host`, `dst_host` and `model` already
//! defined, so it may not mention them at all.
//!
//! Module-level functions must be re-created over each connection's globals.
//! They are, by running a *definitions module*: the script's source with every
//! line outside a top-level `def` blanked out, so each function compiles to
//! the same code (same file, lines and names) as in the full script. For that
//! to bind exactly the same functions, each `def` must be at top level, its
//! name bound by nothing else, its defaults literals and its annotations
//! names that are bound only by imports (or not at all, i.e. builtins).
use rustpython_vm::compiler::parser::ast::{self, Constant, Expr, Ranged, Stmt};
use rustpython_vm::compiler::parser::{self, Mode};
use std::collections::{HashMap, HashSet};

/// CensorLab's native modules, the only ones a script can import
const NATIVE_MODULES: &[&str] = &["rust", "dns", "tls", "quic"];

/// Names defined before the module body runs; the body may not mention them
const CONNECTION_NAMES: &[&str] = &["packet", "host", "dst_host", "model"];

/// Builtins that may be called (or referenced) at module level: they only
/// build or inspect values
const PURE_BUILTINS: &[&str] = &[
    "abs", "all", "any", "bool", "bytearray", "bytes", "chr", "dict", "divmod", "enumerate",
    "float", "frozenset", "int", "len", "list", "max", "min", "ord", "range", "reversed",
    "round", "set", "sorted", "str", "sum", "tuple", "zip",
];

/// Native functions that may be called at module level: they build immutable
/// values and have no side effects
const PURE_NATIVE_FUNCTIONS: &[(&str, &str)] =
    &[("rust", "regex"), ("rust", "subnet"), ("rust", "ip_in")];

/// Methods of builtin types (str, bytes, bytearray, list, dict, set, tuple)
/// that may be called at module level. Mutating ones only ever reach values
/// the body itself built.
const PURE_METHODS: &[&str] = &[
    "add", "append", "copy", "count", "decode", "encode", "endswith", "extend", "find",
    "fromhex", "fromkeys", "get", "hex", "index", "insert", "items", "join", "keys", "lower",
    "lstrip", "maketrans", "replace", "rstrip", "split", "startswith", "strip", "translate",
    "update", "upper", "values",
];

/// A module body recognised as pure
#[derive(Debug)]
pub struct PureModule {
    /// Names of the top-level functions, in definition order
    pub functions: Vec<String>,
    /// Names bound only by imports
    pub imported: HashSet<String>,
    /// The definitions module: the source with only the top-level `def`
    /// statements left, each on its original lines
    pub definitions_source: String,
}

/// How a module-level name is bound
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    Import { module: &'static str },
    Def,
    Other,
}

/// Every module-level binding of each name, and the native function an
/// imported name refers to
#[derive(Default)]
struct Bindings {
    of: HashMap<String, Vec<Binding>>,
    native: HashMap<String, (&'static str, String)>,
}
impl Bindings {
    fn kinds(&self, name: &str) -> &[Binding] {
        self.of.get(name).map_or(&[], Vec::as_slice)
    }
    fn is_bound(&self, name: &str) -> bool {
        self.of.contains_key(name)
    }
    fn only_imported(&self, name: &str) -> bool {
        let kinds = self.kinds(name);
        kinds.len() == 1 && matches!(kinds[0], Binding::Import { .. })
    }
}

/// Decide whether `source`'s module body is pure. `Err` gives the first
/// reason it is not (or a parse error).
pub fn recognize(source: &str, path: &str) -> Result<PureModule, String> {
    let module = parser::parse(source, Mode::Module, path).map_err(|e| e.to_string())?;
    let ast::Mod::Module(module) = module else {
        return Err("not a module".to_owned());
    };
    let line_of = LineIndex::new(source);
    let mut bindings = Bindings::default();
    collect_bindings(&module.body, &mut bindings)?;
    let mut checker = Checker {
        bindings: &bindings,
        line_of: &line_of,
        local: Vec::new(),
    };
    let mut functions = Vec::new();
    let mut def_lines = Vec::new();
    for stmt in &module.body {
        if let Stmt::FunctionDef(def) = stmt {
            checker.function_def(def)?;
            functions.push(def.name.as_str().to_owned());
            let range = def.range();
            def_lines.push((line_of.line(range.start().into()), line_of.line(range.end().into())));
        } else {
            checker.statement(stmt)?;
        }
    }
    // The definitions module keeps exactly the lines of the top-level defs
    let mut definitions_source = String::with_capacity(source.len());
    for (number, line) in source.split_inclusive('\n').enumerate() {
        if def_lines.iter().any(|&(first, last)| (first..=last).contains(&number)) {
            definitions_source.push_str(line);
        } else if line.ends_with('\n') {
            definitions_source.push('\n');
        }
    }
    let imported = bindings
        .of
        .keys()
        .filter(|name| bindings.only_imported(name))
        .cloned()
        .collect();
    Ok(PureModule {
        functions,
        imported,
        definitions_source,
    })
}

/// 0-based line numbers of byte offsets
struct LineIndex {
    starts: Vec<usize>,
}
impl LineIndex {
    fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
        Self { starts }
    }
    fn line(&self, offset: u32) -> usize {
        let offset = offset as usize;
        self.starts.partition_point(|&start| start <= offset) - 1
    }
}

fn collect_bindings(body: &[Stmt], bindings: &mut Bindings) -> Result<(), String> {
    for stmt in body {
        match stmt {
            Stmt::Import(import) => {
                for alias in &import.names {
                    let module = native_module(alias.name.as_str())?;
                    let name = alias.asname.as_ref().unwrap_or(&alias.name).as_str();
                    bind(bindings, name, Binding::Import { module });
                }
            }
            Stmt::ImportFrom(import) => {
                if import.level.as_ref().is_some_and(|level| level.to_u32() != 0) {
                    return Err("relative import".to_owned());
                }
                let module = native_module(import.module.as_ref().map_or("", |m| m.as_str()))?;
                for alias in &import.names {
                    if alias.name.as_str() == "*" {
                        return Err("star import".to_owned());
                    }
                    let name = alias.asname.as_ref().unwrap_or(&alias.name).as_str();
                    bind(bindings, name, Binding::Import { module });
                    bindings
                        .native
                        .insert(name.to_owned(), (module, alias.name.as_str().to_owned()));
                }
            }
            Stmt::FunctionDef(def) => bind(bindings, def.name.as_str(), Binding::Def),
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    bind_target(target, bindings)?;
                }
            }
            Stmt::AugAssign(assign) => bind_target(&assign.target, bindings)?,
            Stmt::AnnAssign(assign) => bind_target(&assign.target, bindings)?,
            Stmt::For(stmt) => {
                bind_target(&stmt.target, bindings)?;
                collect_bindings(&stmt.body, bindings)?;
                collect_bindings(&stmt.orelse, bindings)?;
            }
            Stmt::If(stmt) => {
                collect_bindings(&stmt.body, bindings)?;
                collect_bindings(&stmt.orelse, bindings)?;
            }
            // Everything else binds nothing, or is rejected by the checker
            _ => {}
        }
    }
    Ok(())
}

fn native_module(name: &str) -> Result<&'static str, String> {
    NATIVE_MODULES
        .iter()
        .find(|module| **module == name)
        .copied()
        .ok_or_else(|| format!("import of `{name}`"))
}

fn bind(bindings: &mut Bindings, name: &str, binding: Binding) {
    bindings.of.entry(name.to_owned()).or_default().push(binding);
}

/// Assignment targets: names, possibly in (nested) tuples or lists
fn bind_target(target: &Expr, bindings: &mut Bindings) -> Result<(), String> {
    match target {
        Expr::Name(name) => {
            bind(bindings, name.id.as_str(), Binding::Other);
            Ok(())
        }
        Expr::Tuple(ast::ExprTuple { elts, .. }) | Expr::List(ast::ExprList { elts, .. }) => {
            elts.iter().try_for_each(|elt| bind_target(elt, bindings))
        }
        _ => Err("assignment to something other than a name".to_owned()),
    }
}

struct Checker<'a> {
    bindings: &'a Bindings,
    line_of: &'a LineIndex,
    /// Names bound by enclosing comprehensions
    local: Vec<String>,
}

impl Checker<'_> {
    fn statement(&mut self, stmt: &Stmt) -> Result<(), String> {
        let line = self.line_of.line(stmt.range().start().into());
        let at = |reason: String| format!("line {}: {reason}", line + 1);
        match stmt {
            // Bindings were checked when they were collected
            Stmt::Import(_) | Stmt::ImportFrom(_) | Stmt::Pass(_) => Ok(()),
            Stmt::Break(_) | Stmt::Continue(_) => Ok(()),
            Stmt::Assign(assign) => {
                for target in &assign.targets {
                    self.target(target).map_err(at)?;
                }
                self.expr(&assign.value).map_err(at)
            }
            Stmt::AugAssign(assign) => {
                self.target(&assign.target).map_err(at)?;
                self.expr(&assign.value).map_err(at)
            }
            Stmt::AnnAssign(assign) => {
                self.target(&assign.target).map_err(at)?;
                self.expr(&assign.annotation).map_err(at)?;
                assign.value.as_deref().map_or(Ok(()), |v| self.expr(v)).map_err(at)
            }
            Stmt::Expr(expr) => self.expr(&expr.value).map_err(at),
            Stmt::If(stmt) => {
                self.expr(&stmt.test).map_err(at)?;
                self.block(&stmt.body)?;
                self.block(&stmt.orelse)
            }
            Stmt::For(stmt) => {
                self.target(&stmt.target).map_err(at)?;
                self.expr(&stmt.iter).map_err(at)?;
                self.block(&stmt.body)?;
                self.block(&stmt.orelse)
            }
            Stmt::FunctionDef(_) => Err(at("function defined inside a block".to_owned())),
            other => Err(at(format!("{} statement", statement_kind(other)))),
        }
    }

    fn block(&mut self, body: &[Stmt]) -> Result<(), String> {
        body.iter().try_for_each(|stmt| self.statement(stmt))
    }

    fn target(&self, target: &Expr) -> Result<(), String> {
        match target {
            Expr::Name(name) => self.not_connection_name(name.id.as_str()),
            Expr::Tuple(ast::ExprTuple { elts, .. }) | Expr::List(ast::ExprList { elts, .. }) => {
                elts.iter().try_for_each(|elt| self.target(elt))
            }
            _ => Err("assignment to something other than a name".to_owned()),
        }
    }

    fn not_connection_name(&self, name: &str) -> Result<(), String> {
        if CONNECTION_NAMES.contains(&name) {
            Err(format!("module level uses `{name}`"))
        } else {
            Ok(())
        }
    }

    fn function_def(&mut self, def: &ast::StmtFunctionDef) -> Result<(), String> {
        let name = def.name.as_str();
        let at = |reason: String| format!("function `{name}`: {reason}");
        self.not_connection_name(name).map_err(at)?;
        if !def.decorator_list.is_empty() {
            return Err(at("decorated".to_owned()));
        }
        if !def.type_params.is_empty() {
            return Err(at("type parameters".to_owned()));
        }
        if self.bindings.kinds(name) != [Binding::Def] {
            return Err(at("name also bound by another statement".to_owned()));
        }
        let args = &def.args;
        for arg in args.posonlyargs.iter().chain(&args.args).chain(&args.kwonlyargs) {
            if let Some(default) = &arg.default {
                if !is_literal(default) {
                    return Err(at(format!("default of `{}` is not a literal", arg.def.arg.as_str())));
                }
            }
            self.annotation(arg.def.annotation.as_deref()).map_err(at)?;
        }
        for arg in [&args.vararg, &args.kwarg].into_iter().flatten() {
            self.annotation(arg.annotation.as_deref()).map_err(at)?;
        }
        self.annotation(def.returns.as_deref()).map_err(at)
    }

    /// Annotations are evaluated again when the function is re-created, so
    /// they may only name things that cannot have changed since
    fn annotation(&self, annotation: Option<&Expr>) -> Result<(), String> {
        let Some(annotation) = annotation else {
            return Ok(());
        };
        match annotation {
            Expr::Constant(_) => Ok(()),
            Expr::Name(name) => {
                let name = name.id.as_str();
                self.not_connection_name(name)?;
                if self.bindings.only_imported(name) || !self.bindings.is_bound(name) {
                    Ok(())
                } else {
                    Err(format!("annotation names `{name}`, which the module body binds"))
                }
            }
            Expr::Attribute(attr) => self.annotation(Some(&attr.value)),
            Expr::Subscript(sub) => {
                self.annotation(Some(&sub.value))?;
                self.annotation(Some(&sub.slice))
            }
            Expr::Tuple(ast::ExprTuple { elts, .. }) | Expr::List(ast::ExprList { elts, .. }) => {
                elts.iter().try_for_each(|elt| self.annotation(Some(elt)))
            }
            Expr::BinOp(op) if op.op == ast::Operator::BitOr => {
                self.annotation(Some(&op.left))?;
                self.annotation(Some(&op.right))
            }
            _ => Err("annotation is not a plain name or literal".to_owned()),
        }
    }

    fn expr(&mut self, expr: &Expr) -> Result<(), String> {
        match expr {
            Expr::Constant(_) => Ok(()),
            Expr::Name(name) => self.name(name.id.as_str()),
            Expr::BoolOp(e) => self.exprs(&e.values),
            Expr::BinOp(e) => {
                self.expr(&e.left)?;
                self.expr(&e.right)
            }
            Expr::UnaryOp(e) => self.expr(&e.operand),
            Expr::IfExp(e) => {
                self.expr(&e.test)?;
                self.expr(&e.body)?;
                self.expr(&e.orelse)
            }
            Expr::Compare(e) => {
                self.expr(&e.left)?;
                self.exprs(&e.comparators)
            }
            Expr::Dict(e) => {
                for key in e.keys.iter().flatten() {
                    self.expr(key)?;
                }
                self.exprs(&e.values)
            }
            Expr::Set(ast::ExprSet { elts, .. })
            | Expr::List(ast::ExprList { elts, .. })
            | Expr::Tuple(ast::ExprTuple { elts, .. }) => self.exprs(elts),
            Expr::Starred(e) => self.expr(&e.value),
            Expr::Subscript(e) => {
                self.expr(&e.value)?;
                self.expr(&e.slice)
            }
            Expr::Slice(e) => [&e.lower, &e.upper, &e.step]
                .into_iter()
                .flatten()
                .try_for_each(|part| self.expr(part)),
            Expr::JoinedStr(e) => self.exprs(&e.values),
            Expr::FormattedValue(e) => {
                self.expr(&e.value)?;
                e.format_spec.as_deref().map_or(Ok(()), |spec| self.expr(spec))
            }
            Expr::ListComp(e) => self.comprehension(&e.generators, &[&e.elt]),
            Expr::SetComp(e) => self.comprehension(&e.generators, &[&e.elt]),
            Expr::GeneratorExp(e) => self.comprehension(&e.generators, &[&e.elt]),
            Expr::DictComp(e) => self.comprehension(&e.generators, &[&e.key, &e.value]),
            Expr::Call(call) => self.call(call),
            Expr::Attribute(attr) => {
                self.expr(&attr.value)?;
                Err(format!("attribute access `.{}`", attr.attr.as_str()))
            }
            Expr::Lambda(_) => Err("lambda".to_owned()),
            Expr::NamedExpr(_) => Err("assignment expression".to_owned()),
            Expr::Await(_) | Expr::Yield(_) | Expr::YieldFrom(_) => {
                Err("await/yield at module level".to_owned())
            }
        }
    }

    fn exprs(&mut self, exprs: &[Expr]) -> Result<(), String> {
        exprs.iter().try_for_each(|e| self.expr(e))
    }

    fn name(&self, name: &str) -> Result<(), String> {
        self.not_connection_name(name)?;
        let local = self.local.iter().any(|local| local == name);
        // Imported objects may only be called (if pure), so the module body
        // can never reach their methods through another name
        if !local
            && self.bindings.kinds(name).iter().any(|b| matches!(b, Binding::Import { .. }))
        {
            return Err(format!("module level uses imported `{name}` other than by calling it"));
        }
        if local
            || self.bindings.is_bound(name)
            || PURE_BUILTINS.contains(&name)
        {
            Ok(())
        } else {
            Err(format!("module level uses `{name}`"))
        }
    }

    fn comprehension(&mut self, generators: &[ast::Comprehension], elts: &[&Expr]) -> Result<(), String> {
        let depth = self.local.len();
        let result = (|| {
            for generator in generators {
                if generator.is_async {
                    return Err("async comprehension".to_owned());
                }
                // The first iterable is evaluated outside the comprehension,
                // later ones inside; both only see pure names
                self.expr(&generator.iter)?;
                self.comprehension_target(&generator.target)?;
                self.exprs(&generator.ifs)?;
            }
            elts.iter().try_for_each(|elt| self.expr(elt))
        })();
        self.local.truncate(depth);
        result
    }

    fn comprehension_target(&mut self, target: &Expr) -> Result<(), String> {
        match target {
            Expr::Name(name) => {
                self.not_connection_name(name.id.as_str())?;
                self.local.push(name.id.as_str().to_owned());
                Ok(())
            }
            Expr::Tuple(ast::ExprTuple { elts, .. }) | Expr::List(ast::ExprList { elts, .. }) => {
                elts.iter().try_for_each(|elt| self.comprehension_target(elt))
            }
            _ => Err("comprehension target is not a name".to_owned()),
        }
    }

    fn call(&mut self, call: &ast::ExprCall) -> Result<(), String> {
        match &*call.func {
            Expr::Name(callee) => {
                let callee = callee.id.as_str();
                self.not_connection_name(callee)?;
                let local = self.local.iter().any(|local| local == callee);
                let pure = if local {
                    false
                } else if self.bindings.is_bound(callee) {
                    self.bindings.only_imported(callee)
                        && self.bindings.native.get(callee).is_some_and(|(module, name)| {
                            PURE_NATIVE_FUNCTIONS.contains(&(*module, name.as_str()))
                        })
                } else {
                    PURE_BUILTINS.contains(&callee)
                };
                if !pure {
                    return Err(format!("module level calls `{callee}`"));
                }
            }
            Expr::Attribute(method) => {
                let name = method.attr.as_str();
                self.expr(&method.value)?;
                // Methods of builtin values only, never of imported objects
                if let Expr::Name(receiver) = &*method.value {
                    if self.bindings.kinds(receiver.id.as_str()).iter().any(|b| *b != Binding::Other) {
                        return Err(format!(
                            "module level calls `{}.{name}`",
                            receiver.id.as_str()
                        ));
                    }
                }
                if !PURE_METHODS.contains(&name) {
                    return Err(format!("module level calls method `.{name}`"));
                }
            }
            _ => return Err("module level calls a computed callee".to_owned()),
        }
        self.exprs(&call.args)?;
        call.keywords.iter().try_for_each(|kw| self.expr(&kw.value))
    }
}

/// Immutable literals: constants, signed numbers and tuples of literals
fn is_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Constant(c) => !matches!(c.value, Constant::Ellipsis),
        Expr::UnaryOp(op) => {
            matches!(op.op, ast::UnaryOp::USub | ast::UnaryOp::UAdd)
                && matches!(&*op.operand, Expr::Constant(c)
                    if matches!(c.value, Constant::Int(_) | Constant::Float(_) | Constant::Complex { .. }))
        }
        Expr::Tuple(t) => t.elts.iter().all(is_literal),
        _ => false,
    }
}

fn statement_kind(stmt: &Stmt) -> &'static str {
    match stmt {
        Stmt::AsyncFunctionDef(_) => "async def",
        Stmt::ClassDef(_) => "class",
        Stmt::Return(_) => "return",
        Stmt::Delete(_) => "del",
        Stmt::TypeAlias(_) => "type alias",
        Stmt::AsyncFor(_) => "async for",
        Stmt::While(_) => "while",
        Stmt::With(_) | Stmt::AsyncWith(_) => "with",
        Stmt::Match(_) => "match",
        Stmt::Raise(_) => "raise",
        Stmt::Try(_) | Stmt::TryStar(_) => "try",
        Stmt::Assert(_) => "assert",
        Stmt::Global(_) => "global",
        Stmt::Nonlocal(_) => "nonlocal",
        _ => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason(source: &str) -> Option<String> {
        recognize(source, "<test>").err()
    }

    #[test]
    fn accepts_pure_bodies() {
        for source in [
            "def process(packet):\n    pass\n",
            "\"\"\"doc\"\"\"\nfrom rust import regex, Packet\nimport dns\nimport tls as t\n\
             RE = regex(r'[a-z]{3}')\nX: int = 3\nX += 1\n",
            "KEYS = [b'a', b'b']\nLOWER = [k.lower() for k in KEYS if len(k) > 0]\n\
             TABLE = bytes(range(0x20)) + bytes(range(0x7f, 0x100))\nS = set(range(3))\n\
             D = {k: i for i, k in enumerate(KEYS)}\nA, B = 1, -2\nT = (1, 2)\n",
            "L = []\nfor i in range(3):\n    if i % 2:\n        L.append(i)\n    else:\n        continue\n",
            "TR = bytes.maketrans(b'ab', b'cd')\nN = len(b'xyz') * 2\nF = f'{N:>4}'\nM = max(1, 2)\n",
            "from rust import Packet\ndef process(packet: Packet, n=1, s='x', t=(1, -2.0), *, k=None) -> None:\n    \
             global n2\n    print(packet)\n",
            "def a():\n    return b()\ndef b():\n    return 1\nHANDLERS = [a, b]\n",
            "from rust import subnet, ip_in\nNET = subnet('10.0.0.0/8')\nOK = ip_in('10.0.0.1', '10.0.0.0/8')\n",
        ] {
            if let Err(err) = recognize(source, "<test>") {
                panic!("rejected ({err}):\n{source}");
            }
        }
    }

    #[test]
    fn rejects_impure_bodies_with_a_reason() {
        for (source, expected) in [
            ("print('hi')\n", "calls `print`"),
            ("X = packet\n", "uses `packet`"),
            ("X = host.state\n", "uses `host`"),
            ("dst_host = 1\n", "uses `dst_host`"),
            ("R = model.evaluate('m', [])\n", "uses `model`"),
            ("def f():\n    return 1\nX = f()\n", "calls `f`"),
            ("class A:\n    pass\n", "class statement"),
            ("global x\n", "global statement"),
            ("x = 1\ndel x\n", "del statement"),
            ("try:\n    x = 1\nexcept Exception:\n    pass\n", "try statement"),
            ("while False:\n    pass\n", "while statement"),
            ("from os import path\n", "import of `os`"),
            ("from rust import *\n", "star import"),
            ("from quic import new_reassembler\nR = new_reassembler()\n", "calls `new_reassembler`"),
            ("from dns import parse\nX = parse(b'')\n", "calls `parse`"),
            ("import dns\nX = dns.parse(b'')\n", "imported `dns`"),
            ("from dns import parse\nP = [parse]\n", "imported `parse`"),
            ("L = []\nL.x = 1\n", "assignment to something other than a name"),
            ("X = (1).real\n", "attribute access `.real`"),
            ("F = lambda: 1\n", "lambda"),
            ("X = (y := 1)\n", "assignment expression"),
            ("X = open('f')\n", "calls `open`"),
            ("X = globals()\n", "calls `globals`"),
            ("X = id(1)\n", "calls `id`"),
            ("X = {}\nX.setdefault(1, 2)\n", "method `.setdefault`"),
            ("def f():\n    pass\nf = 1\n", "also bound by another statement"),
            ("def f():\n    pass\ndef f():\n    pass\n", "also bound by another statement"),
            ("if True:\n    def f():\n        pass\n", "function defined inside a block"),
            ("def deco(f):\n    return f\n@deco\ndef g():\n    pass\n", "decorated"),
            ("D = []\ndef f(x=D):\n    pass\n", "not a literal"),
            ("T = int\ndef f(x: T):\n    pass\n", "module body binds"),
            ("def f(x: packet):\n    pass\n", "uses `packet`"),
            ("X = [print for _ in range(1)]\n", "uses `print`"),
        ] {
            match reason(source) {
                Some(reason) => assert!(
                    reason.contains(expected),
                    "expected a reason containing {expected:?}, got {reason:?}:\n{source}"
                ),
                None => panic!("accepted:\n{source}"),
            }
        }
    }

    #[test]
    fn definitions_module_keeps_def_lines_only() {
        let source = "X = 1\ndef f(a=1):\n    return X\n\nY = [\n    2,\n]\ndef g(): return f()\n";
        let module = recognize(source, "<test>").unwrap();
        assert_eq!(module.functions, ["f", "g"]);
        assert_eq!(
            module.definitions_source,
            "\ndef f(a=1):\n    return X\n\n\n\n\ndef g(): return f()\n"
        );
    }
}
