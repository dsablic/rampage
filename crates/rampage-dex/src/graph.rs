//! The app's call graph across every DEX file of an APK: direct and static invokes, virtual and interface invokes
//! resolved through the class hierarchy of all the DEX files (to the method the receiver's class chain defines,
//! and by name to the overriding methods of app subclasses and implementers), callbacks (an app class with a
//! framework supertype instantiated by a method), and component starts (a method loading a component class with
//! `const-class` and invoking an API that starts it). Every pass is bounded by [`GraphLimits`], and every bound hit
//! is noted, so a report can say its evidence is incomplete.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::rc::Rc;

use crate::dex::{Dex, NO_INDEX, cut};
use crate::insn::decode_all;

/// Work bounds of [`AppGraph::build`].
#[derive(Debug, Clone, Copy)]
pub struct GraphLimits {
    /// Method nodes (defined and referenced).
    pub max_methods: usize,
    /// Edges in all.
    pub max_edges: usize,
    /// By-name targets per resolved method reference.
    pub max_targets: usize,
    /// Candidates checked per by-name resolution.
    pub max_candidates: usize,
    /// Const-strings kept per method.
    pub max_strings: usize,
    /// Code units decoded in all.
    pub max_code_units: usize,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_methods: 2_000_000,
            max_edges: 8_000_000,
            max_targets: 32,
            max_candidates: 4096,
            max_strings: 64,
            max_code_units: 64 << 20,
        }
    }
}

/// How a caller reaches a callee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EdgeKind {
    /// invoke-direct, invoke-static or invoke-super, or a call of a framework API.
    Direct,
    /// invoke-virtual or invoke-interface resolved through the receiver class's chain to the method it defines.
    Virtual,
    /// A component class loaded with const-class beside an API that starts it (startService, a work request...).
    Intent,
    /// An app class with a framework supertype instantiated by the caller: the framework may call its methods.
    Callback,
    /// A virtual or interface invoke resolved by name and prototype to an overriding method of an app subclass or
    /// implementer: possible, not shown.
    ByName,
}

impl EdgeKind {
    pub fn label(self) -> &'static str {
        match self {
            EdgeKind::Direct => "direct",
            EdgeKind::Virtual => "virtual",
            EdgeKind::Intent => "starts component",
            EdgeKind::Callback => "registers callback",
            EdgeKind::ByName => "by_name",
        }
    }
}

/// A method node: one the app defines, or one its code references (a framework or library API).
#[derive(Debug, Clone)]
pub struct Method {
    /// Smali text, `Lpkg/Class;->name(params)ret`.
    pub text: String,
    pub class: String,
    pub name: String,
    /// `(params)ret`.
    pub proto: String,
    pub defined: bool,
    pub access: u32,
    /// The DEX file (index into the files given) that defines it.
    pub dex: usize,
    pub method_idx: u32,
    pub code_off: u32,
}

impl Method {
    pub fn is_static(&self) -> bool {
        self.access & 0x8 != 0
    }

    pub fn is_native(&self) -> bool {
        self.access & crate::dex::ACC_NATIVE != 0
    }
}

/// A class the app defines.
#[derive(Debug, Clone)]
pub struct Class {
    pub descriptor: String,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<u32>,
    pub dex: usize,
    /// Its class_def index in that DEX file.
    pub index: u32,
}

/// APIs whose use means some calls are not seen: reflection and code loaded at run time.
const INDIRECT_APIS: &[(&str, &str)] = &[
    ("Ljava/lang/reflect/Method;->invoke", "reflection (Method.invoke)"),
    ("Ljava/lang/reflect/Constructor;->newInstance", "reflection (Constructor.newInstance)"),
    ("Ljava/lang/Class;->forName", "reflection (Class.forName)"),
    ("Ljava/lang/Class;->newInstance", "reflection (Class.newInstance)"),
    ("Ljava/lang/Class;->getMethod", "reflection (Class.getMethod)"),
    ("Ljava/lang/Class;->getDeclaredMethod", "reflection (Class.getDeclaredMethod)"),
    ("Ljava/lang/ClassLoader;->loadClass", "dynamic loading (ClassLoader.loadClass)"),
    ("Ldalvik/system/DexClassLoader;-><init>", "dynamic loading (DexClassLoader)"),
    ("Ldalvik/system/PathClassLoader;-><init>", "dynamic loading (PathClassLoader)"),
    ("Ldalvik/system/InMemoryDexClassLoader;-><init>", "dynamic loading (InMemoryDexClassLoader)"),
    ("Ldalvik/system/BaseDexClassLoader;-><init>", "dynamic loading (BaseDexClassLoader)"),
];

/// Whether a callee text loads code at run time (not only reflects on loaded code).
pub fn loads_code(what: &str) -> bool {
    what.starts_with("dynamic loading")
}

/// Calls that start the component a const-class names.
const STARTS: &[&str] = &[
    "startService",
    "startForegroundService",
    "bindService",
    "startActivity",
    "startActivities",
    "startActivityForResult",
    "sendBroadcast",
    "sendOrderedBroadcast",
    "enqueueWork",
    "setClass",
    "setComponent",
];
/// Constructors and factories taking a component class.
const START_CLASSES: &[&str] = &[
    "Landroid/content/Intent;-><init>",
    "Landroid/content/ComponentName;-><init>",
    "Landroidx/work/OneTimeWorkRequest$Builder;-><init>",
    "Landroidx/work/PeriodicWorkRequest$Builder;-><init>",
    "Landroidx/work/OneTimeWorkRequest;->from",
    "Landroid/app/job/JobInfo$Builder;-><init>",
];
/// Methods the platform calls on a started component.
pub const ENTRY_NAMES: &[&str] = &[
    "onCreate",
    "onStartCommand",
    "onStart",
    "onHandleIntent",
    "onHandleWork",
    "onBind",
    "onReceive",
    "doWork",
    "startWork",
    "onStartJob",
    "onResume",
];

/// Callback methods linked per instantiated class.
const MAX_CALLBACKS: usize = 16;
/// Const-classes and new-instances kept per method.
const MAX_TYPES: usize = 16;
/// Superclass and interface levels an ancestry walk follows, and types it collects.
const MAX_LEVELS: usize = 64;
const MAX_ANCESTORS: usize = 256;

/// Per-method facts gathered while decoding.
#[derive(Default)]
struct Facts {
    classes: Vec<String>,
    instances: Vec<String>,
}

/// The call graph and code facts of an app.
#[derive(Default)]
pub struct AppGraph {
    pub methods: Vec<Method>,
    ids: HashMap<String, u32>,
    pub classes: HashMap<String, Class>,
    pub callees: Vec<Vec<(u32, EdgeKind)>>,
    pub callers: Vec<Vec<(u32, EdgeKind)>>,
    /// Const-strings each defined method loads (the first [`GraphLimits::max_strings`]).
    pub strings: BTreeMap<u32, Vec<String>>,
    /// Methods that call a reflection or dynamic-loading API, with what.
    pub indirect: BTreeMap<u32, &'static str>,
    /// Bounds hit while building, as sentences.
    pub notes: BTreeSet<String>,
    pub edges: usize,
    ancestry: HashMap<String, Rc<HashSet<String>>>,
    limits: GraphLimits,
}

/// A breadth-first walk from one method: each method reached with its distance and the next method toward the
/// start, and whether a bound stopped it.
#[derive(Debug, Default)]
pub struct Walk {
    pub reached: BTreeMap<u32, (usize, Option<(u32, EdgeKind)>)>,
    pub cut: bool,
}

impl Walk {
    pub fn depth(&self, method: u32) -> Option<usize> {
        self.reached.get(&method).map(|&(depth, _)| depth)
    }

    /// The chain from `from` back to the walk's start, each method with the edge toward the next.
    pub fn chain(&self, from: u32) -> Vec<(u32, Option<EdgeKind>)> {
        let mut chain = Vec::new();
        let mut at = from;
        while let Some(&(_, next)) = self.reached.get(&at) {
            chain.push((at, next.map(|(_, edge)| edge)));
            if chain.len() > self.reached.len() {
                break;
            }
            match next {
                Some((method, _)) => at = method,
                None => break,
            }
        }
        chain
    }

    /// Whether any edge on the chain from `from` is of `kind`.
    pub fn chain_has(&self, from: u32, kind: EdgeKind) -> bool {
        self.chain(from).iter().any(|(_, edge)| *edge == Some(kind))
    }
}

/// `Lpkg/Class;->name(params)ret` split into class, name and `(params)ret`.
fn split_text(text: &str) -> (&str, &str, &str) {
    let (class, rest) = text.split_once("->").unwrap_or((text, ""));
    let at = rest.find('(').unwrap_or(rest.len());
    (class, &rest[..at], &rest[at..])
}

impl AppGraph {
    /// Builds the graph of `dexes` (multidex order: the first definition of a class wins, as at run time).
    pub fn build(dexes: &[&Dex], limits: GraphLimits) -> Self {
        let mut graph = AppGraph { limits, ..AppGraph::default() };
        let mut bodies: Vec<u32> = Vec::new();
        for (dex_index, dex) in dexes.iter().enumerate() {
            let mut budget = dex.limits.max_members;
            for class_index in 0..dex.class_count() {
                let Ok(class) = dex.class_def(class_index) else { continue };
                let descriptor = dex.type_text(class.class_idx);
                if graph.classes.contains_key(&descriptor) {
                    graph.notes.insert(
                        "a class is defined in more than one DEX file; the first definition is used".to_owned(),
                    );
                    continue;
                }
                let superclass = (class.superclass_idx != NO_INDEX).then(|| dex.type_text(class.superclass_idx));
                let interfaces = dex
                    .interfaces(&class, MAX_LEVELS)
                    .map(|(list, _)| list.iter().map(|index| dex.type_text(u32::from(*index))).collect())
                    .unwrap_or_default();
                let mut methods = Vec::new();
                if let Ok(data) = dex.class_data(&class, &mut budget) {
                    for encoded in data.methods() {
                        let Ok(reference) = dex.method(encoded.method_idx) else { continue };
                        let text = reference.text();
                        if graph.ids.get(&text).is_some_and(|&id| graph.methods[id as usize].defined) {
                            continue;
                        }
                        let Some(id) = graph.intern(&text) else { break };
                        let method = &mut graph.methods[id as usize];
                        method.defined = true;
                        method.access = encoded.access;
                        method.dex = dex_index;
                        method.method_idx = encoded.method_idx;
                        method.code_off = encoded.code_off;
                        methods.push(id);
                        if encoded.code_off != 0 {
                            bodies.push(id);
                        }
                    }
                }
                graph.classes.insert(
                    descriptor.clone(),
                    Class { descriptor, superclass, interfaces, methods, dex: dex_index, index: class_index },
                );
            }
        }
        let mut sites: Vec<(u32, u32)> = Vec::new();
        let mut facts: BTreeMap<u32, Facts> = BTreeMap::new();
        let mut callee_cache: HashMap<(usize, u32), Option<u32>> = HashMap::new();
        let mut units_left = limits.max_code_units;
        for caller in bodies {
            let (dex_index, code_off) = {
                let method = &graph.methods[caller as usize];
                (method.dex, method.code_off)
            };
            let dex = dexes[dex_index];
            let Ok(code) = dex.code_item(code_off) else { continue };
            if code.insns.len() > units_left {
                graph.notes.insert(format!("only the first {} code units were read", limits.max_code_units));
                break;
            }
            units_left -= code.insns.len();
            let mut fact = Facts::default();
            for insn in decode_all(&code.insns) {
                let Some(index) = insn.index else { continue };
                match insn.opcode {
                    0x1a | 0x1b => {
                        let strings = graph.strings.entry(caller).or_default();
                        if strings.len() < limits.max_strings
                            && let Ok(text) = dex.string(index)
                        {
                            strings.push(cut(&text.text));
                        }
                    }
                    0x1c if fact.classes.len() < MAX_TYPES => fact.classes.push(dex.type_text(index)),
                    0x22 if fact.instances.len() < MAX_TYPES => fact.instances.push(dex.type_text(index)),
                    0x6e..=0x72 | 0x74..=0x78 => {
                        let callee = *callee_cache
                            .entry((dex_index, index))
                            .or_insert_with(|| graph.intern(&dex.method_text(index)));
                        let Some(callee) = callee else { continue };
                        if let Some((_, what)) = INDIRECT_APIS
                            .iter()
                            .find(|(prefix, _)| graph.methods[callee as usize].text.starts_with(prefix))
                        {
                            graph.indirect.entry(caller).or_insert(what);
                        }
                        if matches!(insn.opcode, 0x6e | 0x72 | 0x74 | 0x78) {
                            sites.push((caller, callee));
                        } else {
                            graph.edge(caller, callee, EdgeKind::Direct);
                        }
                    }
                    0xfa..=0xfd => {
                        graph.indirect.entry(caller).or_insert("method handle or invoke-custom");
                    }
                    _ => {}
                }
            }
            if !fact.classes.is_empty() || !fact.instances.is_empty() {
                facts.insert(caller, fact);
            }
        }
        graph.resolve_sites(sites);
        graph.link_facts(&facts);
        for list in graph.callees.iter_mut().chain(graph.callers.iter_mut()) {
            list.sort_unstable();
            list.dedup();
        }
        graph
    }

    fn intern(&mut self, text: &str) -> Option<u32> {
        if let Some(&id) = self.ids.get(text) {
            return Some(id);
        }
        if self.methods.len() >= self.limits.max_methods {
            self.notes.insert(format!("only the first {} methods were graphed", self.limits.max_methods));
            return None;
        }
        let id = self.methods.len() as u32;
        let (class, name, proto) = split_text(text);
        self.methods.push(Method {
            text: text.to_owned(),
            class: class.to_owned(),
            name: name.to_owned(),
            proto: proto.to_owned(),
            defined: false,
            access: 0,
            dex: 0,
            method_idx: NO_INDEX,
            code_off: 0,
        });
        self.callees.push(Vec::new());
        self.callers.push(Vec::new());
        self.ids.insert(text.to_owned(), id);
        Some(id)
    }

    fn edge(&mut self, caller: u32, callee: u32, kind: EdgeKind) {
        if self.edges >= self.limits.max_edges {
            self.notes.insert(format!("only the first {} call edges were graphed", self.limits.max_edges));
            return;
        }
        self.edges += 1;
        self.callees[caller as usize].push((callee, kind));
        self.callers[callee as usize].push((caller, kind));
    }

    /// The method node with smali text `text`.
    pub fn id(&self, text: &str) -> Option<u32> {
        self.ids.get(text).copied()
    }

    pub fn method(&self, id: u32) -> &Method {
        &self.methods[id as usize]
    }

    /// The types `class` extends or implements, transitively through the app's classes (framework types are
    /// included but not walked: their own supertypes are not in the app), `class` itself excluded.
    pub fn ancestors(&mut self, class: &str) -> Rc<HashSet<String>> {
        if let Some(found) = self.ancestry.get(class) {
            return Rc::clone(found);
        }
        let mut found = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::from([(class.to_owned(), 0)]);
        while let Some((at, level)) = queue.pop_front() {
            let Some(defined) = self.classes.get(&at) else { continue };
            if level >= MAX_LEVELS {
                continue;
            }
            for parent in defined.superclass.iter().chain(&defined.interfaces) {
                if found.len() >= MAX_ANCESTORS {
                    break;
                }
                if parent != class && found.insert(parent.clone()) {
                    queue.push_back((parent.clone(), level + 1));
                }
            }
        }
        let found = Rc::new(found);
        self.ancestry.insert(class.to_owned(), Rc::clone(&found));
        found
    }

    /// The framework (non-app) types among `class`'s ancestors, `java.lang.Object` excluded.
    pub fn framework_ancestors(&mut self, class: &str) -> Vec<String> {
        let ancestors = self.ancestors(class);
        let mut found: Vec<String> = ancestors
            .iter()
            .filter(|name| !self.classes.contains_key(*name) && name.as_str() != "Ljava/lang/Object;")
            .cloned()
            .collect();
        found.sort();
        found
    }

    /// The first class up `class`'s superclass chain that the app does not define.
    fn framework_base(&self, class: &str) -> Option<String> {
        let mut at = class.to_owned();
        for _ in 0..MAX_LEVELS {
            let defined = self.classes.get(&at)?;
            let parent = defined.superclass.clone()?;
            if !self.classes.contains_key(&parent) {
                return Some(parent);
            }
            at = parent;
        }
        None
    }

    /// The method named `name` with prototype `proto` that `class` or its nearest app superclass defines.
    fn lookup(&self, class: &str, name: &str, proto: &str) -> Option<u32> {
        let mut at = class.to_owned();
        for _ in 0..MAX_LEVELS {
            let defined = self.classes.get(&at)?;
            if let Some(&id) = defined.methods.iter().find(|&&id| {
                let method = &self.methods[id as usize];
                method.name == name && method.proto == proto
            }) {
                return Some(id);
            }
            at = defined.superclass.clone()?;
        }
        None
    }

    /// Resolves every virtual and interface invoke, once per distinct method reference.
    fn resolve_sites(&mut self, sites: Vec<(u32, u32)>) {
        let mut by_key: HashMap<(String, String), Vec<u32>> = HashMap::new();
        for (id, method) in self.methods.iter().enumerate() {
            if method.defined && !method.is_static() && !method.name.starts_with('<') {
                by_key.entry((method.name.clone(), method.proto.clone())).or_default().push(id as u32);
            }
        }
        let mut resolved: HashMap<u32, Vec<(u32, EdgeKind)>> = HashMap::new();
        for (caller, callee) in sites {
            let targets = match resolved.get(&callee) {
                Some(targets) => targets.clone(),
                None => {
                    let targets = self.resolve(callee, &by_key);
                    resolved.insert(callee, targets.clone());
                    targets
                }
            };
            for (target, kind) in targets {
                self.edge(caller, target, kind);
            }
        }
    }

    fn resolve(&mut self, callee: u32, by_key: &HashMap<(String, String), Vec<u32>>) -> Vec<(u32, EdgeKind)> {
        let (class, name, proto) = {
            let method = &self.methods[callee as usize];
            (method.class.clone(), method.name.clone(), method.proto.clone())
        };
        let mut targets = Vec::new();
        let primary = self.lookup(&class, &name, &proto);
        match primary {
            Some(found) => targets.push((found, EdgeKind::Virtual)),
            None => {
                // An API inherited from the framework: name the framework class, so API tables match it.
                let api = match self.framework_base(&class) {
                    Some(base) => self.intern(&format!("{base}->{name}{proto}")).unwrap_or(callee),
                    None => callee,
                };
                targets.push((api, EdgeKind::Direct));
            }
        }
        if class == "Ljava/lang/Object;" {
            return targets;
        }
        let Some(candidates) = by_key.get(&(name, proto)) else { return targets };
        let mut checked = 0usize;
        let mut cut = false;
        for &candidate in candidates {
            if Some(candidate) == primary {
                continue;
            }
            checked += 1;
            if checked > self.limits.max_candidates {
                cut = true;
                break;
            }
            let owner = self.methods[candidate as usize].class.clone();
            if owner == class || !self.ancestors(&owner).contains(&class) {
                continue;
            }
            if targets.len() > self.limits.max_targets {
                cut = true;
                break;
            }
            targets.push((candidate, EdgeKind::ByName));
        }
        if cut {
            self.notes.insert(format!(
                "a virtual or interface call had more than {} possible targets by name (or {} candidates); the rest \
                 are not linked",
                self.limits.max_targets, self.limits.max_candidates
            ));
        }
        targets
    }

    /// Links callbacks (app classes with a framework supertype instantiated by a method) and component starts.
    fn link_facts(&mut self, facts: &BTreeMap<u32, Facts>) {
        for (&caller, fact) in facts {
            for class in &fact.instances {
                if !self.classes.contains_key(class) || self.framework_ancestors(class).is_empty() {
                    continue;
                }
                let methods: Vec<u32> = self.classes[class]
                    .methods
                    .iter()
                    .copied()
                    .filter(|&id| {
                        let method = &self.methods[id as usize];
                        !method.is_static() && !method.name.starts_with('<')
                    })
                    .take(MAX_CALLBACKS)
                    .collect();
                for method in methods {
                    self.edge(caller, method, EdgeKind::Callback);
                }
            }
            if fact.classes.is_empty() {
                continue;
            }
            let starts = self.callees[caller as usize].iter().any(|&(callee, _)| {
                let method = &self.methods[callee as usize];
                STARTS.contains(&method.name.as_str())
                    || START_CLASSES.iter().any(|prefix| method.text.starts_with(prefix))
            });
            if !starts {
                continue;
            }
            for class in &fact.classes {
                let Some(defined) = self.classes.get(class) else { continue };
                let entries: Vec<u32> = defined
                    .methods
                    .iter()
                    .copied()
                    .filter(|&id| ENTRY_NAMES.contains(&self.methods[id as usize].name.as_str()))
                    .collect();
                for entry in entries {
                    self.edge(caller, entry, EdgeKind::Intent);
                }
            }
        }
    }

    /// The callers of `start`, breadth first, up to `max_depth` levels and `max_visited` methods.
    pub fn callers_walk(&self, start: u32, max_depth: usize, max_visited: usize) -> Walk {
        self.walk(start, max_depth, max_visited, &self.callers)
    }

    /// The callees of `start`, breadth first, up to `max_depth` levels and `max_visited` methods.
    pub fn callees_walk(&self, start: u32, max_depth: usize, max_visited: usize) -> Walk {
        self.walk(start, max_depth, max_visited, &self.callees)
    }

    fn walk(&self, start: u32, max_depth: usize, max_visited: usize, next: &[Vec<(u32, EdgeKind)>]) -> Walk {
        let mut walk = Walk { reached: BTreeMap::from([(start, (0, None))]), cut: false };
        let mut queue = VecDeque::from([start]);
        while let Some(method) = queue.pop_front() {
            let depth = walk.reached[&method].0;
            let Some(neighbours) = next.get(method as usize) else { continue };
            if depth == max_depth {
                walk.cut |= neighbours.iter().any(|(other, _)| !walk.reached.contains_key(other));
                continue;
            }
            for &(other, edge) in neighbours {
                if walk.reached.contains_key(&other) {
                    continue;
                }
                if walk.reached.len() >= max_visited {
                    walk.cut = true;
                    break;
                }
                walk.reached.insert(other, (depth + 1, Some((method, edge))));
                queue.push_back(other);
            }
            if walk.cut && walk.reached.len() >= max_visited {
                break;
            }
        }
        walk
    }

    /// The defined methods that call `api` (a method node), with the edge.
    pub fn callers_of(&self, api: u32) -> &[(u32, EdgeKind)] {
        &self.callers[api as usize]
    }
}
