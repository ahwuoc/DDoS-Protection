use anyhow::{Result, anyhow};
use std::borrow::Cow;
use nftables::batch::Batch;
use nftables::expr::{CT, Expression, NamedExpression, Payload, PayloadField};
use nftables::helper;
use nftables::schema::*;
use nftables::stmt;
use nftables::types::*;
use super::constants::*;

pub(crate) fn apply(batch: Batch) -> Result<()> {
    let nft = batch.to_nftables();
    helper::apply_ruleset(&nft).map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

pub(crate) fn payload(protocol: &str, field: &str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Owned(protocol.to_string()),
            field: Cow::Owned(field.to_string()),
        },
    )))
}

pub(crate) fn ct_state() -> Expression<'static> {
    Expression::Named(NamedExpression::CT(CT {
        key: Cow::Borrowed("state"),
        ..Default::default()
    }))
}

pub(crate) fn str_expr(s: &str) -> Expression<'static> {
    Expression::String(Cow::Owned(s.to_string()))
}

pub(crate) fn set_expr(elements: Vec<Expression<'static>>) -> Expression<'static> {
    Expression::List(elements)
}

pub(crate) fn match_stmt<'a>(
    left: Expression<'a>,
    op: stmt::Operator,
    right: Expression<'a>,
) -> stmt::Statement<'a> {
    stmt::Statement::Match(stmt::Match { left, right, op })
}

pub(crate) fn drop_stmt<'a>() -> stmt::Statement<'a> {
    stmt::Statement::Drop(Some(stmt::Drop {}))
}

pub(crate) fn accept_stmt<'a>() -> stmt::Statement<'a> {
    stmt::Statement::Accept(Some(stmt::Accept {}))
}

pub(crate) fn limit_stmt<'a>(rate: u64, unit: &str, burst: u32, over: bool) -> stmt::Statement<'a> {
    stmt::Statement::Limit(stmt::Limit {
        rate: rate as u32,
        per: Some(Cow::Owned(unit.to_string())),
        burst: Some(burst),
        inv: Some(over),
        rate_unit: None,
        burst_unit: None,
    })
}

pub(crate) fn rule_with<'a>(stmts: Vec<stmt::Statement<'a>>) -> Rule<'a> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(TABLE),
        chain: Cow::Borrowed(CHAIN),
        expr: Cow::Owned(stmts),
        ..Default::default()
    }
}
