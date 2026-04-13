use std::borrow::Cow;
use std::net::Ipv4Addr;

use nftables::batch::Batch;
use nftables::expr::{CT, Expression, NamedExpression, Payload, PayloadField};
use nftables::helper;
use nftables::schema::*;
use nftables::stmt;
use nftables::types::*;

const TABLE: &str = "firewall";
const CHAIN: &str = "input";
const SET_BAN: &str = "ban_ip";

pub struct KernelFirewall;

impl KernelFirewall {
    pub fn new() -> Self {
        let fw = Self;
        fw.setup().expect("❌ Failed to init nftables");
        fw
    }

    fn apply(batch: Batch) -> Result<(), Box<dyn std::error::Error>> {
        let nft = batch.to_nftables();
        helper::apply_ruleset(&nft)?;
        Ok(())
    }

    fn payload(protocol: &str, field: &str) -> Expression<'static> {
        Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Owned(protocol.to_string()),
                field: Cow::Owned(field.to_string()),
            },
        )))
    }

    fn ct_state() -> Expression<'static> {
        Expression::Named(NamedExpression::CT(CT {
            key: Cow::Borrowed("state"),
            ..Default::default()
        }))
    }

    fn str_expr(s: &str) -> Expression<'static> {
        Expression::String(Cow::Owned(s.to_string()))
    }

    fn match_stmt<'a>(
        left: Expression<'a>,
        op: stmt::Operator,
        right: Expression<'a>,
    ) -> stmt::Statement<'a> {
        stmt::Statement::Match(stmt::Match { left, right, op })
    }

    fn drop_stmt<'a>() -> stmt::Statement<'a> {
        stmt::Statement::Drop(Some(stmt::Drop {}))
    }

    fn rule_with<'a>(stmts: Vec<stmt::Statement<'a>>) -> Rule<'a> {
        Rule {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            chain: Cow::Borrowed(CHAIN),
            expr: Cow::Owned(stmts),
            ..Default::default()
        }
    }

    // ── Setup: table + chain + ban_ip set + drop rule ───────
    pub fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();

        batch.add(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(TABLE),
            ..Default::default()
        }));

        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(CHAIN),
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Input),
            prio: Some(0),
            policy: Some(NfChainPolicy::Accept),
            ..Default::default()
        }));

        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            ..Default::default()
        })));

        // ip saddr @ban_ip → drop
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("ip", "saddr"),
                stmt::Operator::IN,
                Self::str_expr(&format!("@{SET_BAN}")),
            ),
            Self::drop_stmt(),
        ])));

        Self::apply(batch)?;
        tracing::info!("✅ KernelFirewall setup: table={TABLE} chain={CHAIN}");
        Ok(())
    }

    // ── Ban IP ──────────────────────────────────────────────
    pub fn ban(&self, ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![Self::str_expr(&ip.to_string())]),
        }));
        Self::apply(batch)?;
        tracing::info!("🚫 Kernel ban: {ip}");
        Ok(())
    }

    // ── Unban IP ────────────────────────────────────────────
    pub fn unban(&self, ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![Self::str_expr(&ip.to_string())]),
        }));
        Self::apply(batch)?;
        tracing::info!("✅ Kernel unban: {ip}");
        Ok(())
    }

    // ── Drop invalid conntrack state ────────────────────────
    pub fn add_invalid_drop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::ct_state(),
                stmt::Operator::EQ,
                Self::str_expr("invalid"),
            ),
            Self::drop_stmt(),
        ])));
        Self::apply(batch)?;
        tracing::info!("✅ Invalid packet drop rule added");
        Ok(())
    }

    // ── SYN flood: drop pure SYN + invalid ct ───────────────
    pub fn add_syn_flood_protection(
        &self,
        _max_syn_per_sec: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("tcp", "flags"),
                stmt::Operator::IN,
                Self::str_expr("syn"),
            ),
            Self::match_stmt(
                Self::ct_state(),
                stmt::Operator::EQ,
                Self::str_expr("invalid"),
            ),
            Self::drop_stmt(),
        ])));
        Self::apply(batch)?;
        tracing::info!("✅ SYN flood protection rule added");
        Ok(())
    }

    // ── Allow only TCP on specific port ─────────────────────
    pub fn add_allow_only_tcp_port(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();

        // Drop non-TCP
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("ip", "protocol"),
                stmt::Operator::NEQ,
                Self::str_expr("tcp"),
            ),
            Self::drop_stmt(),
        ])));

        // Drop TCP not on game port
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("tcp", "dport"),
                stmt::Operator::NEQ,
                Expression::Number(port as u32),
            ),
            Self::drop_stmt(),
        ])));

        Self::apply(batch)?;
        tracing::info!("✅ Allow only TCP port {port}");
        Ok(())
    }

    // ── Teardown: delete entire table ───────────────────────
    pub fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(TABLE),
            ..Default::default()
        }));
        Self::apply(batch)?;
        tracing::info!("🧹 KernelFirewall teardown done");
        Ok(())
    }
}
