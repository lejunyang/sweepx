use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sweepx_cleaner_schema::{
    CleanerRule, MAX_AST_DEPTH, MAX_AST_NODES, MonotonicRaise, Predicate, PredicateArg,
    PredicateOp, RiskTier, UnknownPolicy, ValidationError,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmValue {
    Bool(bool),
    String(String),
    StringList(Vec<String>),
    NestedStringList(Vec<Vec<String>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalState {
    Known(bool),
    Unknown,
}

impl EvalState {
    pub fn is_true(&self) -> bool {
        matches!(self, Self::Known(true))
    }
}

#[derive(Debug, Default, Clone)]
pub struct EvaluationContext {
    fields: BTreeMap<String, VmValue>,
}

impl EvaluationContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(mut self, key: impl Into<String>, value: VmValue) -> Self {
        self.fields.insert(key.into(), value);
        self
    }

    pub fn get(&self, key: &str) -> Option<&VmValue> {
        self.fields.get(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEvaluation {
    pub fact_state: EvalState,
    pub inference_state: EvalState,
    pub resolved_risk: RiskTier,
    pub report_only: bool,
}

pub fn evaluate_rule(
    rule: &CleanerRule,
    context: &EvaluationContext,
) -> Result<RuleEvaluation, VmError> {
    rule.validate().map_err(VmError::InvalidRule)?;

    let fact_state = evaluate_all(&rule.analysis.fact_predicates, context)?;
    let inference_state = evaluate_all(&rule.analysis.inference_predicates, context)?;
    let resolved_risk = resolve_risk(rule, context)?;
    let report_only = match rule.analysis.unknown_policy {
        UnknownPolicy::ReportOnly => {
            matches!(fact_state, EvalState::Unknown)
                || matches!(inference_state, EvalState::Unknown)
        }
        UnknownPolicy::Block => resolved_risk == RiskTier::Blocked,
        UnknownPolicy::RaiseRisk => false,
    };

    Ok(RuleEvaluation {
        fact_state,
        inference_state,
        resolved_risk,
        report_only,
    })
}

pub fn evaluate_predicate(
    predicate: &Predicate,
    context: &EvaluationContext,
) -> Result<EvalState, VmError> {
    let (depth, nodes) = predicate.metrics();
    if depth > MAX_AST_DEPTH {
        return Err(VmError::ResourceLimit(ResourceLimitError::Depth {
            depth,
            max: MAX_AST_DEPTH,
        }));
    }
    if nodes > MAX_AST_NODES {
        return Err(VmError::ResourceLimit(ResourceLimitError::Nodes {
            nodes,
            max: MAX_AST_NODES,
        }));
    }
    eval(predicate, context)
}

fn resolve_risk(rule: &CleanerRule, context: &EvaluationContext) -> Result<RiskTier, VmError> {
    let mut risk = rule.risk.floor;
    for raise in &rule.risk.monotonic_raises {
        match evaluate_predicate(&raise.when, context)? {
            EvalState::Known(true) => {
                if raise.to < risk {
                    return Err(VmError::InvalidRiskTransition {
                        from: risk,
                        to: raise.to,
                    });
                }
                risk = raise.to;
            }
            EvalState::Known(false) => {}
            EvalState::Unknown => match rule.analysis.unknown_policy {
                UnknownPolicy::RaiseRisk => {
                    risk = promote_unknown_risk(risk);
                }
                UnknownPolicy::ReportOnly => {}
                UnknownPolicy::Block => risk = RiskTier::Blocked,
            },
        }
    }
    Ok(risk)
}

fn promote_unknown_risk(risk: RiskTier) -> RiskTier {
    match risk {
        RiskTier::R1 => RiskTier::R2,
        RiskTier::R2 => RiskTier::R3,
        RiskTier::R3 | RiskTier::R4 | RiskTier::Blocked => risk,
    }
}

fn evaluate_all(
    predicates: &[Predicate],
    context: &EvaluationContext,
) -> Result<EvalState, VmError> {
    let mut saw_unknown = false;
    for predicate in predicates {
        match evaluate_predicate(predicate, context)? {
            EvalState::Known(true) => {}
            EvalState::Known(false) => return Ok(EvalState::Known(false)),
            EvalState::Unknown => saw_unknown = true,
        }
    }
    Ok(if saw_unknown {
        EvalState::Unknown
    } else {
        EvalState::Known(true)
    })
}

fn eval(predicate: &Predicate, context: &EvaluationContext) -> Result<EvalState, VmError> {
    match predicate {
        Predicate::Call { op, args } => match op {
            PredicateOp::And => eval_and(args, context),
            PredicateOp::Or => eval_or(args, context),
            PredicateOp::Not => eval_not(args, context),
            PredicateOp::Eq => eval_eq(args, context),
            PredicateOp::In => eval_in(args, context),
            PredicateOp::Exists => eval_exists(args, context),
            PredicateOp::StateIs => eval_eq(args, context),
            PredicateOp::VersionIn => eval_version_in(args, context),
            PredicateOp::IsDescendantOf => eval_descendant_of(args, context),
            PredicateOp::SetIntersects => eval_set_intersects(args, context),
        },
    }
}

fn eval_and(args: &[PredicateArg], context: &EvaluationContext) -> Result<EvalState, VmError> {
    let mut saw_unknown = false;
    for arg in args {
        match eval_arg_as_bool(arg, context)? {
            EvalState::Known(true) => {}
            EvalState::Known(false) => return Ok(EvalState::Known(false)),
            EvalState::Unknown => saw_unknown = true,
        }
    }
    Ok(if saw_unknown {
        EvalState::Unknown
    } else {
        EvalState::Known(true)
    })
}

fn eval_or(args: &[PredicateArg], context: &EvaluationContext) -> Result<EvalState, VmError> {
    let mut saw_unknown = false;
    for arg in args {
        match eval_arg_as_bool(arg, context)? {
            EvalState::Known(true) => return Ok(EvalState::Known(true)),
            EvalState::Known(false) => {}
            EvalState::Unknown => saw_unknown = true,
        }
    }
    Ok(if saw_unknown {
        EvalState::Unknown
    } else {
        EvalState::Known(false)
    })
}

fn eval_not(args: &[PredicateArg], context: &EvaluationContext) -> Result<EvalState, VmError> {
    match eval_arg_as_bool(&args[0], context)? {
        EvalState::Known(value) => Ok(EvalState::Known(!value)),
        EvalState::Unknown => Ok(EvalState::Unknown),
    }
}

fn eval_eq(args: &[PredicateArg], context: &EvaluationContext) -> Result<EvalState, VmError> {
    let Some(left) = resolve_value(&args[0], context)? else {
        return Ok(EvalState::Unknown);
    };
    let Some(right) = resolve_value(&args[1], context)? else {
        return Ok(EvalState::Unknown);
    };
    Ok(EvalState::Known(left == right))
}

fn eval_in(args: &[PredicateArg], context: &EvaluationContext) -> Result<EvalState, VmError> {
    let Some(needle) = resolve_value(&args[0], context)? else {
        return Ok(EvalState::Unknown);
    };
    let Some(haystack) = resolve_value(&args[1], context)? else {
        return Ok(EvalState::Unknown);
    };

    let result = match (needle, haystack) {
        (VmValue::String(value), VmValue::StringList(values)) => values.iter().any(|v| v == &value),
        (VmValue::StringList(value), VmValue::NestedStringList(values)) => {
            values.iter().any(|v| v == &value)
        }
        _ => return Err(VmError::TypeMismatch("in".into())),
    };
    Ok(EvalState::Known(result))
}

fn eval_exists(args: &[PredicateArg], context: &EvaluationContext) -> Result<EvalState, VmError> {
    match &args[0] {
        PredicateArg::FieldRef { field } => Ok(EvalState::Known(context.get(field).is_some())),
        _ => Err(VmError::TypeMismatch(
            "exists requires a field reference".into(),
        )),
    }
}

fn eval_version_in(
    args: &[PredicateArg],
    context: &EvaluationContext,
) -> Result<EvalState, VmError> {
    let Some(VmValue::String(version)) = resolve_value(&args[0], context)? else {
        return Ok(EvalState::Unknown);
    };
    let Some(VmValue::String(requirement)) = resolve_value(&args[1], context)? else {
        return Ok(EvalState::Unknown);
    };
    let version = semver::Version::parse(&version).map_err(|_| VmError::InvalidVersion(version))?;
    let requirement = semver::VersionReq::parse(&requirement)
        .map_err(|_| VmError::InvalidVersionRequirement(requirement))?;
    Ok(EvalState::Known(requirement.matches(&version)))
}

fn eval_descendant_of(
    args: &[PredicateArg],
    context: &EvaluationContext,
) -> Result<EvalState, VmError> {
    let Some(VmValue::String(path)) = resolve_value(&args[0], context)? else {
        return Ok(EvalState::Unknown);
    };
    let Some(VmValue::String(parent)) = resolve_value(&args[1], context)? else {
        return Ok(EvalState::Unknown);
    };
    if path == parent {
        return Ok(EvalState::Known(false));
    }
    Ok(EvalState::Known(
        path.starts_with(&format!("{parent}/")) || path.starts_with(&format!("{parent}\\")),
    ))
}

fn eval_set_intersects(
    args: &[PredicateArg],
    context: &EvaluationContext,
) -> Result<EvalState, VmError> {
    let Some(VmValue::StringList(left)) = resolve_value(&args[0], context)? else {
        return Ok(EvalState::Unknown);
    };
    let Some(VmValue::StringList(right)) = resolve_value(&args[1], context)? else {
        return Ok(EvalState::Unknown);
    };
    let left: BTreeSet<_> = left.into_iter().collect();
    let right: BTreeSet<_> = right.into_iter().collect();
    Ok(EvalState::Known(!left.is_disjoint(&right)))
}

fn eval_arg_as_bool(arg: &PredicateArg, context: &EvaluationContext) -> Result<EvalState, VmError> {
    let Some(value) = resolve_value(arg, context)? else {
        return Ok(EvalState::Unknown);
    };
    match value {
        VmValue::Bool(value) => Ok(EvalState::Known(value)),
        _ => Err(VmError::TypeMismatch("boolean predicate".into())),
    }
}

fn resolve_value(
    arg: &PredicateArg,
    context: &EvaluationContext,
) -> Result<Option<VmValue>, VmError> {
    match arg {
        PredicateArg::FieldRef { field } => Ok(context.get(field).cloned()),
        PredicateArg::Predicate(predicate) => match evaluate_predicate(predicate, context)? {
            EvalState::Known(value) => Ok(Some(VmValue::Bool(value))),
            EvalState::Unknown => Ok(None),
        },
        PredicateArg::String(value) => Ok(Some(VmValue::String(value.clone()))),
        PredicateArg::Bool(value) => Ok(Some(VmValue::Bool(*value))),
        PredicateArg::StringList(values) => Ok(Some(VmValue::StringList(values.clone()))),
        PredicateArg::NestedStringList(values) => {
            Ok(Some(VmValue::NestedStringList(values.clone())))
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VmError {
    #[error("invalid rule: {0}")]
    InvalidRule(ValidationError),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(ResourceLimitError),
    #[error("type mismatch in {0}")]
    TypeMismatch(String),
    #[error("invalid risk transition from {from} to {to}")]
    InvalidRiskTransition { from: RiskTier, to: RiskTier },
    #[error("invalid semver version: {0}")]
    InvalidVersion(String),
    #[error("invalid semver requirement: {0}")]
    InvalidVersionRequirement(String),
    #[error("invalid json context value for {0}")]
    InvalidContextValue(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResourceLimitError {
    #[error("depth {depth} exceeds max {max}")]
    Depth { depth: usize, max: usize },
    #[error("nodes {nodes} exceeds max {max}")]
    Nodes { nodes: usize, max: usize },
}

impl TryFrom<BTreeMap<String, Value>> for EvaluationContext {
    type Error = VmError;

    fn try_from(value: BTreeMap<String, Value>) -> Result<Self, Self::Error> {
        let mut fields = BTreeMap::new();
        for (key, value) in value {
            let vm_value = match value {
                Value::Bool(v) => VmValue::Bool(v),
                Value::String(v) => VmValue::String(v),
                Value::Array(values) => {
                    if values.iter().all(Value::is_string) {
                        VmValue::StringList(
                            values
                                .into_iter()
                                .map(|value| value.as_str().unwrap_or_default().to_owned())
                                .collect(),
                        )
                    } else if values.iter().all(|value| {
                        value
                            .as_array()
                            .map(|inner| inner.iter().all(Value::is_string))
                            .unwrap_or(false)
                    }) {
                        let empty: Vec<Value> = Vec::new();
                        VmValue::NestedStringList(
                            values
                                .into_iter()
                                .map(|value| {
                                    value
                                        .as_array()
                                        .unwrap_or(&empty)
                                        .iter()
                                        .map(|inner| inner.as_str().unwrap_or_default().to_owned())
                                        .collect()
                                })
                                .collect(),
                        )
                    } else {
                        return Err(VmError::InvalidContextValue(key));
                    }
                }
                _ => return Err(VmError::InvalidContextValue(key)),
            };
            fields.insert(key, vm_value);
        }
        Ok(Self { fields })
    }
}

pub fn resolve_monotonic_raises(
    raises: &[MonotonicRaise],
    base: RiskTier,
    context: &EvaluationContext,
    unknown_policy: UnknownPolicy,
) -> Result<RiskTier, VmError> {
    let mut risk = base;
    for raise in raises {
        match evaluate_predicate(&raise.when, context)? {
            EvalState::Known(true) => {
                if raise.to < risk {
                    return Err(VmError::InvalidRiskTransition {
                        from: risk,
                        to: raise.to,
                    });
                }
                risk = risk.max(raise.to);
            }
            EvalState::Known(false) => {}
            EvalState::Unknown => {
                risk = match unknown_policy {
                    UnknownPolicy::RaiseRisk => promote_unknown_risk(risk),
                    UnknownPolicy::ReportOnly => risk,
                    UnknownPolicy::Block => RiskTier::Blocked,
                };
            }
        }
    }
    Ok(risk)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sweepx_cleaner_schema::CleanerRule;

    use super::*;

    fn rule() -> CleanerRule {
        serde_json::from_value(json!({
            "schema": "sweepx.cleaner-rule/v1",
            "id": "chromium-cache-v1",
            "artifactClass": "rebuildable-browser-cache",
            "platforms": [{"os": "linux", "arch": ["x86_64"]}],
            "rootRef": {"kind": "probe-verified-profile-cache-root", "evidence": "chromium.profile-state.v1"},
            "discovery": {"effectClass": "z0", "capabilities": ["filesystem.metadata.read.scoped"], "nativeProbeId": "probe", "semanticReadOnly": true, "zeroWriteVerified": true, "unknownVersionBehavior": "report_only"},
            "selectors": [{"kind": "exact-relative-components", "values": [["Cache"], ["Code Cache"]]}],
            "requiredEvidence": ["browser.product-version-channel.v1"],
            "optionalEvidence": [],
            "exclusionEvidence": ["browser.running-or-unknown.v1"],
            "grouping": "directory",
            "analysis": {
                "factPredicates": [{"op": "in", "args": [{"field": "candidate.relativeComponents"}, [["Cache"], ["Code Cache"]]]}],
                "inferencePredicates": [{"op": "eq", "args": [{"field": "browser.profileStillness"}, "verified"]}],
                "unknownPolicy": "report_only"
            },
            "risk": {
                "floor": "R2",
                "monotonicRaises": [{
                    "when": {"op": "or", "args": [{"op": "eq", "args": [{"field": "browser.runningState"}, "running"]}, {"op": "state_is", "args": [{"field": "browser.layout"}, "unknown"]}]},
                    "to": "BLOCKED"
                }]
            },
            "proposal": {"disposition": "eligible_with_confirmation", "supportedAction": "filesystemTrash", "targetGranularity": "whole-verified-cache-root"},
            "recoveryRequirements": ["browser can regenerate cache"],
            "activityBlockers": ["browser running"],
            "sharingRules": ["bind to exact profile"],
            "explanationKeys": ["browser.cache-rebuild"],
            "references": ["chromium-layout-adapter@tested-milestone"]
        }))
        .expect("rule parses")
    }

    #[test]
    fn evaluates_known_true_paths() {
        let context = EvaluationContext::new()
            .insert(
                "candidate.relativeComponents",
                VmValue::StringList(vec!["Cache".into()]),
            )
            .insert(
                "browser.profileStillness",
                VmValue::String("verified".into()),
            )
            .insert("browser.runningState", VmValue::String("stopped".into()))
            .insert("browser.layout", VmValue::String("known".into()));
        let result = evaluate_rule(&rule(), &context).expect("evaluates");
        assert_eq!(result.fact_state, EvalState::Known(true));
        assert_eq!(result.inference_state, EvalState::Known(true));
        assert_eq!(result.resolved_risk, RiskTier::R2);
        assert!(!result.report_only);
    }

    #[test]
    fn unknown_field_triggers_report_only() {
        let context = EvaluationContext::new()
            .insert(
                "candidate.relativeComponents",
                VmValue::StringList(vec!["Code Cache".into()]),
            )
            .insert("browser.runningState", VmValue::String("stopped".into()));
        let result = evaluate_rule(&rule(), &context).expect("evaluates");
        assert_eq!(result.inference_state, EvalState::Unknown);
        assert!(result.report_only);
    }

    #[test]
    fn resource_limit_depth_is_enforced() {
        let mut predicate = json!({"field": "x"});
        for _ in 0..(MAX_AST_DEPTH + 1) {
            predicate = json!({"op": "not", "args": [predicate]});
        }
        let predicate: Predicate = serde_json::from_value(predicate).expect("parse predicate");
        let err =
            evaluate_predicate(&predicate, &EvaluationContext::new()).expect_err("depth limit");
        assert!(matches!(
            err,
            VmError::ResourceLimit(ResourceLimitError::Depth { .. })
        ));
    }

    #[test]
    fn resource_limit_nodes_is_enforced() {
        let mut args = Vec::with_capacity(MAX_AST_NODES + 2);
        for i in 0..(MAX_AST_NODES + 1) {
            args.push(json!({"op": "exists", "args": [{"field": format!("f{i}")}]}));
        }
        let predicate: Predicate =
            serde_json::from_value(json!({"op": "or", "args": args})).expect("parse predicate");
        let err =
            evaluate_predicate(&predicate, &EvaluationContext::new()).expect_err("node limit");
        assert!(matches!(
            err,
            VmError::ResourceLimit(ResourceLimitError::Nodes { .. })
        ));
    }

    #[test]
    fn cannot_lower_risk_even_if_vm_called_directly() {
        let context = EvaluationContext::new();
        let err = resolve_monotonic_raises(
            &[MonotonicRaise {
                when: serde_json::from_value(json!({"op": "exists", "args": [{"field": "x"}]}))
                    .expect("predicate"),
                to: RiskTier::R1,
            }],
            RiskTier::R2,
            &context,
            UnknownPolicy::ReportOnly,
        );
        assert_eq!(err.expect("vm uses max semantics"), RiskTier::R2);
    }
}
