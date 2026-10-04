use crate::{repository::Snapshot, RungError};
use rung_model::{Capability, Confidence, EvidenceKind, EvidenceObservation, PresenceDisposition};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use syn::visit::Visit;
use syn::{Attribute, Ident, Item, Visibility};
use tracing::instrument;

fn safe_path(value: &str) -> Result<&str, RungError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(RungError::Config(format!("invalid evidence path: {value}")));
    }
    Ok(value)
}

pub(crate) fn normalize_route(value: &str) -> Result<String, RungError> {
    let (method, path) = value
        .split_once(' ')
        .ok_or_else(|| RungError::Config("route evidence must be METHOD /path".into()))?;
    if method.is_empty()
        || !method.chars().all(|c| c.is_ascii_alphabetic())
        || !path.starts_with('/')
        || path.chars().any(char::is_whitespace)
    {
        return Err(RungError::Config(
            "route evidence must be METHOD /path".into(),
        ));
    }
    Ok(format!("{} {path}", method.to_ascii_uppercase()))
}

#[derive(Default)]
pub(crate) struct Surface {
    pub symbols: BTreeSet<String>,
    pub tests: BTreeSet<String>,
    pub cli_commands: BTreeSet<String>,
    pub routes: BTreeSet<String>,
    pub test_locations: BTreeMap<String, BTreeSet<String>>,
    pub cli_locations: BTreeMap<String, BTreeSet<String>>,
    pub route_locations: BTreeMap<String, BTreeSet<String>>,
    pub public_api: BTreeMap<String, BTreeSet<String>>,
    pub configuration: BTreeMap<String, BTreeSet<String>>,
}

pub(crate) struct CargoFeature {
    pub package: String,
    pub feature: String,
    pub path: String,
}

struct Indexer<'a> {
    file: &'a str,
    surface: &'a mut Surface,
}

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "delete", "patch", "head", "options", "trace", "connect",
];

fn note(
    map: &mut BTreeMap<String, BTreeSet<String>>,
    set: &mut BTreeSet<String>,
    file: &str,
    value: &str,
) {
    set.insert(value.to_string());
    map.entry(value.to_string())
        .or_default()
        .insert(file.to_string());
}

fn is_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn derive_idents(attrs: &[Attribute]) -> Vec<String> {
    let mut names = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let Ok(nested) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        ) else {
            continue;
        };
        for path in nested {
            if let Some(segment) = path.segments.last() {
                names.push(segment.ident.to_string());
            }
        }
    }
    names
}

fn command_string(attrs: &[Attribute], key: &str) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("command") {
            continue;
        }
        let mut found = None;
        let parsed = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident(key) {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                found = Some(lit.value());
                Ok(())
            } else if meta.input.peek(syn::Token![=]) {
                let _: syn::Token![=] = meta.input.parse()?;
                let _: syn::Expr = meta.input.parse()?;
                Ok(())
            } else if meta.input.peek(syn::token::Paren) {
                let content;
                syn::parenthesized!(content in meta.input);
                let _ = content;
                Ok(())
            } else {
                Ok(())
            }
        });
        if parsed.is_ok() {
            if let Some(name) = found.filter(|name| !name.is_empty()) {
                return Some(name);
            }
        }
    }
    None
}

fn kebab_case(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (index, &ch) in chars.iter().enumerate() {
        if ch == '_' {
            out.push('-');
            continue;
        }
        if ch.is_uppercase() {
            let prev_lower = index > 0 && chars[index - 1].is_lowercase();
            let prev_upper = index > 0 && chars[index - 1].is_uppercase();
            let next_lower = chars.get(index + 1).is_some_and(|ch| ch.is_lowercase());
            if index > 0 && (prev_lower || (prev_upper && next_lower)) {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_test_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
}

fn attr_first_string(attr: &Attribute) -> Option<String> {
    attr.parse_args_with(|input: syn::parse::ParseStream| {
        if input.is_empty() || !input.peek(syn::LitStr) {
            return Ok(None);
        }
        let lit: syn::LitStr = input.parse()?;
        Ok(Some(lit.value()))
    })
    .ok()
    .flatten()
}

fn http_method(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    HTTP_METHODS.iter().copied().find(|method| *method == lower)
}

fn route_from_attr(attr: &Attribute) -> Option<String> {
    let method = attr.path().segments.last()?.ident.to_string();
    let method = http_method(&method)?;
    let path = attr_first_string(attr)?;
    if !path.starts_with('/') || path.chars().any(char::is_whitespace) {
        return None;
    }
    Some(format!("{} {path}", method.to_ascii_uppercase()))
}

fn path_last_ident(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn collect_route_methods(expr: &syn::Expr, found: &mut Vec<String>) {
    match expr {
        syn::Expr::Call(call) => {
            if let Some(name) = path_last_ident(&call.func) {
                if let Some(method) = http_method(&name) {
                    found.push(method.to_ascii_uppercase());
                }
            }
        }
        syn::Expr::MethodCall(call) => {
            if let Some(method) = http_method(&call.method.to_string()) {
                found.push(method.to_ascii_uppercase());
            }
            collect_route_methods(&call.receiver, found);
        }
        _ => {}
    }
}

fn string_lit(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(lit),
            ..
        }) => Some(lit.value()),
        _ => None,
    }
}

impl Indexer<'_> {
    fn note_symbol(&mut self, name: &str) {
        self.surface.symbols.insert(name.to_string());
    }

    fn note_test(&mut self, name: &str) {
        note(
            &mut self.surface.test_locations,
            &mut self.surface.tests,
            self.file,
            name,
        );
    }

    fn note_cli(&mut self, name: &str) {
        if name.is_empty() || name.chars().any(char::is_whitespace) {
            return;
        }
        note(
            &mut self.surface.cli_locations,
            &mut self.surface.cli_commands,
            self.file,
            name,
        );
    }

    fn note_route(&mut self, route: &str) {
        note(
            &mut self.surface.route_locations,
            &mut self.surface.routes,
            self.file,
            route,
        );
    }

    fn record_public_name(&mut self, vis: &Visibility, ident: &Ident) {
        if is_public(vis) {
            self.note_symbol(&ident.to_string());
        }
    }

    fn record_tests(&mut self, attrs: &[Attribute], ident: &Ident) {
        if attrs.iter().any(is_test_attr) {
            self.note_test(&ident.to_string());
        }
    }

    fn record_attr_routes(&mut self, attrs: &[Attribute]) {
        for attr in attrs {
            if let Some(route) = route_from_attr(attr) {
                self.note_route(&route);
            }
        }
    }

    fn record_route_args(&mut self, args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>) {
        let Some(path_expr) = args.first() else {
            return;
        };
        let Some(path) = string_lit(path_expr) else {
            return;
        };
        if !path.starts_with('/') || path.chars().any(char::is_whitespace) {
            return;
        }
        let Some(methods_expr) = args.iter().nth(1) else {
            return;
        };
        let mut methods = Vec::new();
        collect_route_methods(methods_expr, &mut methods);
        for method in methods {
            self.note_route(&format!("{method} {path}"));
        }
    }

    fn record_cli_struct(&mut self, attrs: &[Attribute]) {
        if derive_idents(attrs).iter().any(|name| name == "Parser") {
            if let Some(name) = command_string(attrs, "name") {
                self.note_cli(&name);
            }
        }
    }

    fn record_cli_enum(&mut self, item: &syn::ItemEnum) {
        let derives = derive_idents(&item.attrs);
        let is_command = derives
            .iter()
            .any(|name| name == "Parser" || name == "Subcommand");
        if !is_command {
            return;
        }
        if derives.iter().any(|name| name == "Parser") {
            if let Some(name) = command_string(&item.attrs, "name") {
                self.note_cli(&name);
            }
        }
        for variant in &item.variants {
            // Clap's default rename is kebab-case. Other rename_all settings are
            // not applied; an explicit `name` is.
            let name = command_string(&variant.attrs, "name")
                .unwrap_or_else(|| kebab_case(&variant.ident.to_string()));
            self.note_cli(&name);
        }
    }

    fn record_use_tree(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Name(name) => self.note_symbol(&name.ident.to_string()),
            syn::UseTree::Rename(name) => self.note_symbol(&name.rename.to_string()),
            syn::UseTree::Path(path) => self.record_use_tree(&path.tree),
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.record_use_tree(tree);
                }
            }
            // A glob re-export is not name-resolved, so it is not symbol evidence.
            syn::UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for Indexer<'_> {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.record_public_name(&item.vis, &item.sig.ident);
        self.record_tests(&item.attrs, &item.sig.ident);
        self.record_attr_routes(&item.attrs);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.record_public_name(&item.vis, &item.sig.ident);
        self.record_tests(&item.attrs, &item.sig.ident);
        self.record_attr_routes(&item.attrs);
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.record_public_name(&item.vis, &item.ident);
        self.record_cli_struct(&item.attrs);
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.record_public_name(&item.vis, &item.ident);
        self.record_cli_enum(item);
        syn::visit::visit_item_enum(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if is_public(&item.vis) {
            self.note_symbol(&item.ident.to_string());
            for trait_item in &item.items {
                match trait_item {
                    syn::TraitItem::Fn(item) => self.note_symbol(&item.sig.ident.to_string()),
                    syn::TraitItem::Const(item) => self.note_symbol(&item.ident.to_string()),
                    syn::TraitItem::Type(item) => self.note_symbol(&item.ident.to_string()),
                    _ => {}
                }
            }
        }
        syn::visit::visit_item_trait(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.record_public_name(&item.vis, &item.ident);
        syn::visit::visit_item_type(self, item);
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.record_public_name(&item.vis, &item.ident);
        syn::visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.record_public_name(&item.vis, &item.ident);
        syn::visit::visit_item_static(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        self.record_public_name(&item.vis, &item.ident);
        syn::visit::visit_item_union(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if is_public(&item.vis) {
            self.record_use_tree(&item.tree);
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_last_ident(&call.func).as_deref() == Some("route") {
            self.record_route_args(&call.args);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "route" {
            self.record_route_args(&call.args);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn file_dir(path: &str) -> &str {
    path.rfind('/').map(|index| &path[..index]).unwrap_or("")
}

fn join_rel(dir: &str, rel: &str) -> String {
    let rel = rel.replace('\\', "/");
    if dir.is_empty() {
        rel
    } else {
        format!("{dir}/{rel}")
    }
}

fn submodule_dir(path: &str) -> String {
    let name = file_name(path);
    if name == "mod.rs" || name == "lib.rs" || name == "main.rs" {
        file_dir(path).to_string()
    } else {
        path.trim_end_matches(".rs").to_string()
    }
}

fn is_crate_root(path: &str) -> bool {
    let name = file_name(path);
    let parent = file_dir(path);
    let parent_name = file_name(parent);
    if (name == "lib.rs" || name == "main.rs") && parent_name == "src" {
        return true;
    }
    if name == "main.rs" && file_name(file_dir(parent)) == "tests" {
        return true;
    }
    if parent_name == "bin" && file_name(file_dir(parent)) == "src" && name.ends_with(".rs") {
        return true;
    }
    parent_name == "tests" && name.ends_with(".rs")
}

fn path_attribute(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        let value = match &attr.meta {
            syn::Meta::NameValue(meta) => match &meta.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(lit),
                    ..
                }) => lit.value(),
                _ => continue,
            },
            syn::Meta::List(_) => match attr.parse_args::<syn::LitStr>() {
                Ok(lit) => lit.value(),
                Err(_) => continue,
            },
            syn::Meta::Path(_) => continue,
        };
        if value.is_empty()
            || value.starts_with('/')
            || Path::new(&value)
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            continue;
        }
        return Some(value);
    }
    None
}

fn resolve_module(
    current: &str,
    name: &str,
    path_attr: Option<&str>,
    files: &BTreeMap<String, syn::File>,
) -> Option<String> {
    if let Some(relative) = path_attr {
        let full = join_rel(file_dir(current), relative);
        return files.contains_key(&full).then_some(full);
    }
    let base = join_rel(&submodule_dir(current), name);
    let rust_file = format!("{base}.rs");
    if files.contains_key(&rust_file) {
        return Some(rust_file);
    }
    let module_file = format!("{base}/mod.rs");
    files.contains_key(&module_file).then_some(module_file)
}

fn configuration_type(name: &str, attrs: &[Attribute]) -> bool {
    (name.ends_with("Config") || name.ends_with("Settings"))
        && derive_idents(attrs)
            .iter()
            .any(|derive| derive == "Deserialize")
}

fn remember(map: &mut BTreeMap<String, BTreeSet<String>>, file: &str, name: &str) {
    map.entry(name.to_string())
        .or_default()
        .insert(file.to_string());
}

fn exported_names(tree: &syn::UseTree, names: &mut Vec<String>) {
    match tree {
        syn::UseTree::Name(name) => names.push(name.ident.to_string()),
        syn::UseTree::Rename(name) => names.push(name.rename.to_string()),
        syn::UseTree::Path(path) => exported_names(&path.tree, names),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                exported_names(tree, names);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn walk_public_item(
    file: &str,
    item: &Item,
    files: &BTreeMap<String, syn::File>,
    seen: &mut BTreeSet<String>,
    surface: &mut Surface,
) {
    match item {
        Item::Fn(item) if is_public(&item.vis) => {
            remember(&mut surface.public_api, file, &item.sig.ident.to_string());
        }
        Item::Struct(item) if is_public(&item.vis) => {
            let name = item.ident.to_string();
            if configuration_type(&name, &item.attrs) {
                remember(&mut surface.configuration, file, &name);
            } else {
                remember(&mut surface.public_api, file, &name);
            }
        }
        Item::Enum(item) if is_public(&item.vis) => {
            let name = item.ident.to_string();
            if configuration_type(&name, &item.attrs) {
                remember(&mut surface.configuration, file, &name);
            } else {
                remember(&mut surface.public_api, file, &name);
            }
        }
        Item::Union(item) if is_public(&item.vis) => {
            remember(&mut surface.public_api, file, &item.ident.to_string());
        }
        Item::Trait(item) if is_public(&item.vis) => {
            remember(&mut surface.public_api, file, &item.ident.to_string());
        }
        Item::Type(item) if is_public(&item.vis) => {
            remember(&mut surface.public_api, file, &item.ident.to_string());
        }
        Item::Const(item) if is_public(&item.vis) => {
            remember(&mut surface.public_api, file, &item.ident.to_string());
        }
        Item::Static(item) if is_public(&item.vis) => {
            remember(&mut surface.public_api, file, &item.ident.to_string());
        }
        Item::Use(item) if is_public(&item.vis) => {
            let mut names = Vec::new();
            exported_names(&item.tree, &mut names);
            for name in names {
                remember(&mut surface.public_api, file, &name);
            }
        }
        Item::Mod(item) if is_public(&item.vis) => {
            if let Some((_, items)) = &item.content {
                for child in items {
                    walk_public_item(file, child, files, seen, surface);
                }
            } else if let Some(path) = resolve_module(
                file,
                &item.ident.to_string(),
                path_attribute(&item.attrs).as_deref(),
                files,
            ) {
                walk_public_file(&path, files, seen, surface);
            }
        }
        _ => {}
    }
}

fn walk_public_file(
    path: &str,
    files: &BTreeMap<String, syn::File>,
    seen: &mut BTreeSet<String>,
    surface: &mut Surface,
) {
    if !seen.insert(path.to_string()) {
        return;
    }
    let Some(ast) = files.get(path) else {
        return;
    };
    for item in &ast.items {
        walk_public_item(path, item, files, seen, surface);
    }
}

pub(crate) fn index(snapshot: &Snapshot) -> Result<Surface, RungError> {
    let mut files = BTreeMap::new();
    for (path, bytes) in &snapshot.files {
        if !path.ends_with(".rs") {
            continue;
        }
        let source = std::str::from_utf8(bytes)
            .map_err(|error| RungError::Analysis(format!("{path}: {error}")))?;
        let ast = syn::parse_file(source)
            .map_err(|error| RungError::Analysis(format!("{path}: {error}")))?;
        files.insert(path.clone(), ast);
    }
    let mut surface = Surface::default();
    for (path, ast) in &files {
        Indexer {
            file: path,
            surface: &mut surface,
        }
        .visit_file(ast);
    }
    let mut seen = BTreeSet::new();
    let roots: Vec<String> = files
        .keys()
        .filter(|path| is_crate_root(path))
        .cloned()
        .collect();
    for root in roots {
        walk_public_file(&root, &files, &mut seen, &mut surface);
    }
    Ok(surface)
}

pub(crate) fn cargo_features(snapshot: &Snapshot) -> Result<Vec<CargoFeature>, RungError> {
    let mut found = Vec::new();
    for (path, bytes) in &snapshot.files {
        if file_name(path) != "Cargo.toml" {
            continue;
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|error| RungError::Analysis(format!("{path}: {error}")))?;
        let value: toml::Value = toml::from_str(text)
            .map_err(|error| RungError::Analysis(format!("{path}: {error}")))?;
        let Some(features) = value.get("features") else {
            continue;
        };
        let toml::Value::Table(table) = features else {
            return Err(RungError::Analysis(format!(
                "{path}: features is not a table"
            )));
        };
        let package = value
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .filter(|name| !name.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                let parent = file_dir(path);
                let name = file_name(parent);
                if name.is_empty() {
                    "workspace".to_string()
                } else {
                    name.to_string()
                }
            });
        for feature in table.keys() {
            if feature.is_empty() {
                continue;
            }
            found.push(CargoFeature {
                package: package.clone(),
                feature: feature.clone(),
                path: path.clone(),
            });
        }
    }
    found.sort_by(|left, right| (&left.path, &left.feature).cmp(&(&right.path, &right.feature)));
    Ok(found)
}

fn cargo_feature_present(features: &[CargoFeature], value: &str) -> bool {
    if let Some((package, feature)) = value.split_once('/') {
        features
            .iter()
            .any(|item| item.package == package && item.feature == feature)
    } else {
        features.iter().any(|item| item.feature == value)
    }
}

#[instrument(skip(capability, snapshot))]
pub fn assess(
    capability: &Capability,
    snapshot: &Snapshot,
) -> Result<(PresenceDisposition, Confidence, Vec<EvidenceObservation>), RungError> {
    let needs_rust = capability.evidence.iter().any(|evidence| {
        matches!(
            evidence.kind,
            EvidenceKind::Symbol
                | EvidenceKind::Test
                | EvidenceKind::CliCommand
                | EvidenceKind::Route
        )
    });
    let needs_cargo = capability
        .evidence
        .iter()
        .any(|evidence| evidence.kind == EvidenceKind::CargoFeature);
    let surface = if needs_rust {
        Some(index(snapshot)?)
    } else {
        None
    };
    let features = if needs_cargo {
        cargo_features(snapshot)?
    } else {
        Vec::new()
    };
    let mut observations = Vec::new();
    let mut found_weight = 0u32;
    let mut total_weight = 0u32;
    for evidence in &capability.evidence {
        let found = match evidence.kind {
            EvidenceKind::File => snapshot.files.contains_key(safe_path(&evidence.value)?),
            EvidenceKind::Symbol => surface
                .as_ref()
                .is_some_and(|surface| surface.symbols.contains(&evidence.value)),
            EvidenceKind::Test => surface
                .as_ref()
                .is_some_and(|surface| surface.tests.contains(&evidence.value)),
            EvidenceKind::CargoFeature => cargo_feature_present(&features, &evidence.value),
            EvidenceKind::CliCommand => surface
                .as_ref()
                .is_some_and(|surface| surface.cli_commands.contains(&evidence.value)),
            EvidenceKind::Route => {
                let route = normalize_route(&evidence.value)?;
                surface
                    .as_ref()
                    .is_some_and(|surface| surface.routes.contains(&route))
            }
        };
        if found {
            found_weight += u32::from(evidence.weight);
        }
        total_weight += u32::from(evidence.weight);
        observations.push(EvidenceObservation {
            kind: evidence.kind,
            value: evidence.value.clone(),
            found,
            weight: evidence.weight,
        });
    }
    let basis_points = (found_weight * 10_000)
        .checked_div(total_weight)
        .unwrap_or(0);
    let confidence = Confidence::new(basis_points as u16)
        .ok_or_else(|| RungError::Analysis("invalid confidence calculation".into()))?;
    let presence = if found_weight >= u32::from(capability.threshold) {
        PresenceDisposition::Present
    } else if found_weight == 0 {
        PresenceDisposition::Absent
    } else {
        PresenceDisposition::ProbablyAbsent
    };
    Ok((presence, confidence, observations))
}
