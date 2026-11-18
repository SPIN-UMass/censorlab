//! Per-connection copies of a PyCL module environment.
//!
//! For a script whose module body is pure (see [`super::module_purity`]), the
//! body runs once at startup and the globals it leaves are captured here,
//! after checking that every value is one this module knows how to share or
//! copy. Each connection then gets its own instance of that environment,
//! indistinguishable from running the body in the connection's globals:
//! * immutable values (None, bool, int, float, str, bytes, tuples and
//!   frozensets of those, compiled regexes and subnets) and imported objects
//!   are shared, as running the body again would produce equal values (and
//!   imports return the very same objects);
//! * lists, dicts, sets and bytearrays are copied, deeply, with aliasing
//!   (two globals naming one list, a list containing itself) preserved;
//! * the module's functions are re-created over the connection's globals by
//!   running the definitions module, so `global` statements and global reads
//!   reach the connection's own dict;
//! * globals are inserted in the order the body inserted them.
//!
//! Anything else in the globals makes the script ineligible at startup.
use super::module_purity::PureModule;
use super::packet::rust_packet::{Regex, Subnet};
use rustpython_vm::builtins::{
    PyByteArray, PyBytes, PyCode, PyDict, PyDictRef, PyFloat, PyFrozenSet, PyInt, PyList, PySet,
    PyStr, PyTuple,
};
use rustpython_vm::scope::Scope;
use rustpython_vm::{AsObject, PyObject, PyObjectRef, PyRef, PyResult, VirtualMachine};
use std::collections::{HashMap, HashSet};

/// Globals the scope already holds when the module body runs
const PRESET_GLOBALS: &[&str] = &["__builtins__", "model"];

/// How a global is instantiated for a connection
#[derive(Debug)]
enum Entry {
    /// Immutable or imported: the same object for every connection
    Shared(PyObjectRef),
    /// Contains something mutable: copied. `functions`: it (or something
    /// in it) is one of the module's functions, so it can only be copied
    /// once those are re-created
    Copied { value: PyObjectRef, functions: bool },
}

/// The environment left by one run of a pure module body
#[derive(Debug)]
pub struct ModuleSnapshot {
    /// The body's globals, in insertion order
    entries: Vec<(PyObjectRef, Entry)>,
    /// Names of the module's functions, re-created per connection
    functions: Vec<String>,
    /// The definitions module (see [`PureModule::definitions_source`])
    definitions: PyRef<PyCode>,
    /// Ids of the snapshot's own functions -> index into `functions`
    function_ids: HashMap<usize, usize>,
}

impl ModuleSnapshot {
    /// Capture `globals`, as left by running the body of `module`. Fails
    /// (with the first reason) if a value is not one that can be shared or
    /// copied.
    pub fn capture(
        vm: &VirtualMachine,
        globals: &PyDictRef,
        module: &PureModule,
        definitions: PyRef<PyCode>,
    ) -> Result<Self, String> {
        // Each top-level def binds its name, and nothing else does (checked
        // on the syntax tree): the value must be that def's function
        let mut function_ids = HashMap::new();
        for (index, name) in module.functions.iter().enumerate() {
            let function = globals
                .get_item_opt(name.as_str(), vm)
                .map_err(|_| format!("`{name}` cannot be looked up"))?
                .ok_or_else(|| format!("function `{name}` is not defined"))?;
            if !own_function(vm, &function, globals) {
                return Err(format!("`{name}` is not a plain function of this module"));
            }
            function_ids.insert(function.get_id(), index);
        }
        let recognizer = Recognizer {
            vm,
            function_ids: &function_ids,
        };
        let mut entries = Vec::new();
        for (key, value) in globals {
            let Some(name) = key.payload_if_exact::<PyStr>(vm) else {
                return Err("a global has a non-string name".to_owned());
            };
            let name = name.as_str();
            if PRESET_GLOBALS.contains(&name) {
                continue;
            }
            let entry = if module.imported.contains(name) {
                Entry::Shared(value)
            } else {
                match recognizer.recognize(&value, &mut HashSet::new()) {
                    Ok(Kind::Immutable) => Entry::Shared(value),
                    Ok(Kind::Mutable { functions }) => Entry::Copied { value, functions },
                    Err(reason) => return Err(format!("global `{name}`: {reason}")),
                }
            };
            entries.push((key, entry));
        }
        Ok(Self {
            entries,
            functions: module.functions.clone(),
            definitions,
            function_ids,
        })
    }

    /// Give `scope` (a fresh connection scope holding `__builtins__`,
    /// `model` and the per-packet globals) its own instance of the
    /// environment, as if the module body had run in it
    pub fn instantiate(&self, vm: &VirtualMachine, scope: &Scope) -> PyResult<()> {
        let globals = &scope.globals;
        let preset = globals.len();
        let mut copier = Copier {
            vm,
            snapshot: self,
            functions: Vec::new(),
            memo: Vec::new(),
        };
        // Every global goes in first, in the body's order; those referring to
        // functions are filled in once the functions exist
        for (key, entry) in &self.entries {
            let value = match entry {
                Entry::Shared(value) => value.clone(),
                Entry::Copied { value, functions: false } => copier.copy(value)?,
                Entry::Copied { functions: true, .. } => vm.ctx.none(),
            };
            globals.set_item(&**key, value, vm)?;
        }
        // Re-create the functions over this connection's globals
        vm.run_code_obj(self.definitions.clone(), scope.clone())?;
        // The definitions module only rebinds def names, which are already
        // present; anything it added (none expected) goes again. Keys are
        // only ever appended, so the extra ones are the last.
        let expected = preset + self.entries.len();
        if globals.len() > expected {
            let extra: Vec<PyObjectRef> =
                globals.into_iter().skip(expected).map(|(key, _)| key).collect();
            for key in extra {
                globals.del_item(&*key, vm)?;
            }
        }
        copier.functions = self
            .functions
            .iter()
            .map(|name| globals.get_item(name.as_str(), vm))
            .collect::<PyResult<Vec<_>>>()?;
        for (key, entry) in &self.entries {
            if let Entry::Copied { value, functions: true } = entry {
                let copy = copier.copy(value)?;
                globals.set_item(&**key, copy, vm)?;
            }
        }
        Ok(())
    }
}

/// Whether `value` is a plain function defined over `globals`
fn own_function(vm: &VirtualMachine, value: &PyObject, globals: &PyDictRef) -> bool {
    value.class().is(vm.ctx.types.function_type)
        && value
            .get_attr("__globals__", vm)
            .is_ok_and(|g| g.is(globals))
        && value
            .get_attr("__closure__", vm)
            .is_ok_and(|closure| vm.is_none(&closure))
}

enum Kind {
    Immutable,
    /// `functions`: refers (perhaps indirectly) to a module function
    Mutable { functions: bool },
}

struct Recognizer<'a> {
    vm: &'a VirtualMachine,
    function_ids: &'a HashMap<usize, usize>,
}
impl Recognizer<'_> {
    /// `visiting`: containers on the current path (a container may contain itself)
    fn recognize(&self, value: &PyObject, visiting: &mut HashSet<usize>) -> Result<Kind, String> {
        let vm = self.vm;
        let types = &vm.ctx.types;
        let class = value.class();
        if vm.is_none(value)
            || class.is(types.bool_type)
            || value.payload_if_exact::<PyInt>(vm).is_some()
            || value.payload_if_exact::<PyFloat>(vm).is_some()
            || value.payload_if_exact::<PyStr>(vm).is_some()
            || value.payload_if_exact::<PyBytes>(vm).is_some()
            || value.payload_if_exact::<Regex>(vm).is_some()
            || value.payload_if_exact::<Subnet>(vm).is_some()
        {
            return Ok(Kind::Immutable);
        }
        if let Some(tuple) = value.payload_if_exact::<PyTuple>(vm) {
            return self.all_immutable(tuple.as_slice().iter(), visiting, "tuple");
        }
        if let Some(set) = value.payload_if_exact::<PyFrozenSet>(vm) {
            return self.all_immutable(set.elements().iter(), visiting, "frozenset");
        }
        if self.function_ids.contains_key(&value.get_id()) {
            return Ok(Kind::Mutable { functions: true });
        }
        let id = value.get_id();
        if visiting.contains(&id) {
            // Whatever it holds is accounted for where it was first reached
            return Ok(Kind::Mutable { functions: false });
        }
        visiting.insert(id);
        let mut functions = false;
        let mut item = |item: &PyObject, visiting: &mut HashSet<usize>| {
            if let Kind::Mutable { functions: true } = self.recognize(item, visiting)? {
                functions = true;
            }
            Ok::<_, String>(())
        };
        let result = if let Some(list) = value.payload_if_exact::<PyList>(vm) {
            let items = list.borrow_vec().to_vec();
            items.iter().try_for_each(|value| item(value, visiting))
        } else if let Some(dict) = value.payload_if_exact::<PyDict>(vm) {
            dict.into_iter().try_for_each(|(key, value)| {
                self.all_immutable(std::iter::once(&key), visiting, "dict key")?;
                item(&value, visiting)
            })
        } else if let Some(set) = value.payload_if_exact::<PySet>(vm) {
            self.all_immutable(set.elements().iter(), visiting, "set").map(drop)
        } else if value.payload_if_exact::<PyByteArray>(vm).is_some() {
            Ok(())
        } else {
            Err(format!("a `{}` value cannot be copied", class.name()))
        };
        visiting.remove(&id);
        result.map(|()| Kind::Mutable { functions })
    }

    fn all_immutable<'v>(
        &self,
        items: impl Iterator<Item = &'v PyObjectRef>,
        visiting: &mut HashSet<usize>,
        what: &str,
    ) -> Result<Kind, String> {
        for item in items {
            if !matches!(self.recognize(item, visiting)?, Kind::Immutable) {
                return Err(format!("{what} holds a mutable value"));
            }
        }
        Ok(Kind::Immutable)
    }
}

/// Deep copy of snapshot values for one connection
struct Copier<'a> {
    vm: &'a VirtualMachine,
    snapshot: &'a ModuleSnapshot,
    /// The connection's functions, in `ModuleSnapshot::functions` order
    /// (empty until they are re-created)
    functions: Vec<PyObjectRef>,
    /// Snapshot container id -> its copy (preserves aliasing and cycles).
    /// Modules hold few containers, so a list beats hashing.
    memo: Vec<(usize, PyObjectRef)>,
}
impl Copier<'_> {
    fn copy(&mut self, value: &PyObjectRef) -> PyResult<PyObjectRef> {
        let vm = self.vm;
        let types = &vm.ctx.types;
        let class = value.class();
        if class.is(types.function_type) {
            // Recognised at capture: one of the module's functions
            let index = self.snapshot.function_ids[&value.get_id()];
            return Ok(self.functions[index].clone());
        }
        if !(class.is(types.list_type)
            || class.is(types.dict_type)
            || class.is(types.set_type)
            || class.is(types.bytearray_type))
        {
            // Recognised at capture as immutable: shared
            return Ok(value.clone());
        }
        let id = value.get_id();
        if let Some((_, copy)) = self.memo.iter().find(|(original, _)| *original == id) {
            return Ok(copy.clone());
        }
        if let Some(list) = value.payload_if_exact::<PyList>(vm) {
            let copy = vm.ctx.new_list(Vec::new());
            self.memo.push((id, copy.clone().into()));
            let items = list.borrow_vec();
            // Exactly sized (collecting a fallible iterator would over-allocate)
            let mut copies = Vec::with_capacity(items.len());
            for item in items.iter() {
                copies.push(self.copy(item)?);
            }
            *copy.borrow_vec_mut() = copies;
            Ok(copy.into())
        } else if let Some(dict) = value.payload_if_exact::<PyDict>(vm) {
            let copy = vm.ctx.new_dict();
            self.memo.push((id, copy.clone().into()));
            for (key, item) in dict {
                let item = self.copy(&item)?;
                copy.set_item(&*key, item, vm)?;
            }
            Ok(copy.into())
        } else if let Some(set) = value.payload_if_exact::<PySet>(vm) {
            // Elements are immutable (recognised at capture), so shared
            let copy = PySet::new_ref(&vm.ctx);
            for item in set.elements() {
                copy.add(item, vm)?;
            }
            let copy: PyObjectRef = copy.into();
            self.memo.push((id, copy.clone()));
            Ok(copy)
        } else {
            let bytes = value
                .payload_if_exact::<PyByteArray>(vm)
                .expect("checked to be a bytearray above");
            let copy: PyObjectRef =
                PyByteArray::new_ref(bytes.borrow_buf().to_vec(), &vm.ctx).into();
            self.memo.push((id, copy.clone()));
            Ok(copy)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::module_purity::recognize;
    use crate::transport::new_python_interpreter;
    use rustpython_vm::compiler::Mode;

    /// Run `source` as a module body once, snapshot it, instantiate it in
    /// `connections` fresh scopes, run `per_connection[i]` (if any) in scope
    /// `i`, then hand everything to `check`
    fn with_instances(
        source: &str,
        per_connection: &[&str],
        check: impl FnOnce(&VirtualMachine, &Scope, &[Scope]),
    ) {
        let interp = new_python_interpreter(1337);
        interp.enter(|vm| {
            vm.import("rust", 0).unwrap();
            let code = vm.compile(source, Mode::Exec, "<test>".to_owned()).unwrap();
            let snapshot_scope = vm.new_scope_with_builtins();
            snapshot_scope.globals.set_item("model", vm.ctx.none(), vm).unwrap();
            vm.run_code_obj(code, snapshot_scope.clone()).unwrap();
            let module = recognize(source, "<test>").expect("pure");
            let definitions = vm
                .compile(&module.definitions_source, Mode::Exec, "<test>".to_owned())
                .unwrap();
            let snapshot =
                ModuleSnapshot::capture(vm, &snapshot_scope.globals, &module, definitions)
                    .expect("recognised");
            let scopes: Vec<Scope> = per_connection
                .iter()
                .map(|code| {
                    let scope = vm.new_scope_with_builtins();
                    scope.globals.set_item("model", vm.ctx.none(), vm).unwrap();
                    snapshot.instantiate(vm, &scope).unwrap();
                    // (run_code_string also sets `__file__`)
                    if code.is_empty() {
                        return scope;
                    }
                    if let Err(err) = vm.run_code_string(scope.clone(), code, "<conn>".to_owned()) {
                        vm.print_exception(err);
                        panic!("connection code raised");
                    }
                    scope
                })
                .collect();
            check(vm, &snapshot_scope, &scopes);
        });
    }

    fn get(vm: &VirtualMachine, scope: &Scope, expr: &str) -> PyObjectRef {
        vm.run_block_expr(scope.clone(), expr).unwrap()
    }

    fn int(vm: &VirtualMachine, scope: &Scope, expr: &str) -> i64 {
        get(vm, scope, expr).try_into_value(vm).unwrap()
    }

    const MODULE: &str = "\
count = 0
L = []
A = L
D = {'k': [1]}
T = (1, b'x', 'y')
F = frozenset([1, 2])
C = []
C.append(C)
def bump():
    global count
    count += 1
    L.append(count)
    D['k'].append(count)
    return count
H = [bump]
";

    #[test]
    fn connections_get_isolated_copies() {
        with_instances(MODULE, &["bump(); bump()", ""], |vm, snapshot, conns| {
            // Global scalars and mutated containers are per connection
            assert_eq!(int(vm, &conns[0], "count"), 2);
            assert_eq!(int(vm, &conns[1], "count"), 0);
            assert_eq!(int(vm, &conns[0], "len(L) * 10 + len(D['k'])"), 23);
            assert_eq!(int(vm, &conns[1], "len(L) * 10 + len(D['k'])"), 1);
            // ... and the snapshot is untouched
            assert_eq!(int(vm, snapshot, "count * 100 + len(L) * 10 + len(D['k'])"), 1);
            assert!(!get(vm, &conns[0], "L").is(&get(vm, &conns[1], "L")));
            assert!(!get(vm, &conns[0], "L").is(&get(vm, snapshot, "L")));
        });
    }

    #[test]
    fn aliasing_and_cycles_are_preserved() {
        with_instances(MODULE, &[""], |vm, _, conns| {
            let conn = &conns[0];
            assert!(get(vm, conn, "A").is(&get(vm, conn, "L")));
            assert!(get(vm, conn, "C[0]").is(&get(vm, conn, "C")));
        });
    }

    #[test]
    fn functions_use_their_connections_globals() {
        with_instances(MODULE, &["H[0]()", ""], |vm, snapshot, conns| {
            for scope in conns {
                assert!(get(vm, scope, "bump.__globals__").is(&scope.globals));
                // Functions inside containers are the connection's own
                assert!(get(vm, scope, "H[0]").is(&get(vm, scope, "bump")));
                assert!(!get(vm, scope, "bump").is(&get(vm, snapshot, "bump")));
            }
            assert_eq!(int(vm, &conns[0], "count"), 1);
            assert_eq!(int(vm, &conns[1], "count"), 0);
            // Same code, name and qualified name as the body's function
            assert!(get(vm, &conns[0], "bump.__code__").is(&get(vm, &conns[1], "bump.__code__")));
            let name = |scope: &Scope| -> String {
                get(vm, scope, "bump.__qualname__ + str(bump.__code__.co_firstlineno)")
                    .try_into_value(vm)
                    .unwrap()
            };
            assert_eq!(name(&conns[0]), name(snapshot));
        });
    }

    #[test]
    fn immutable_values_are_shared() {
        with_instances(MODULE, &["", ""], |vm, snapshot, conns| {
            for expr in ["T", "F"] {
                assert!(get(vm, &conns[0], expr).is(&get(vm, snapshot, expr)));
                assert!(get(vm, &conns[1], expr).is(&get(vm, snapshot, expr)));
            }
        });
    }

    #[test]
    fn globals_keep_the_bodys_order() {
        with_instances(MODULE, &[""], |vm, snapshot, conns| {
            let keys = "[k for k in globals() if k != '__builtins__']";
            let names = |scope: &Scope| -> Vec<String> {
                get(vm, scope, keys).try_into_value(vm).unwrap()
            };
            assert_eq!(names(&conns[0]), names(snapshot));
        });
    }

    #[test]
    fn unrecognised_values_are_rejected() {
        let interp = new_python_interpreter(1337);
        interp.enter(|vm| {
            vm.import("rust", 0).unwrap();
            for (source, reason) in [
                ("R = range(3)\n", "`range` value cannot be copied"),
                ("T = (1, [2])\n", "tuple holds a mutable value"),
                ("I = iter(())\n", ""),
            ] {
                // iter() is not even pure: recognised as such first
                let Ok(module) = recognize(source, "<test>") else {
                    assert!(reason.is_empty(), "{source}");
                    continue;
                };
                let code = vm.compile(source, Mode::Exec, "<test>".to_owned()).unwrap();
                let scope = vm.new_scope_with_builtins();
                vm.run_code_obj(code, scope.clone()).unwrap();
                let definitions = vm
                    .compile(&module.definitions_source, Mode::Exec, "<test>".to_owned())
                    .unwrap();
                let err = ModuleSnapshot::capture(vm, &scope.globals, &module, definitions)
                    .expect_err(source);
                assert!(err.contains(reason), "{err}");
            }
        });
    }
}
