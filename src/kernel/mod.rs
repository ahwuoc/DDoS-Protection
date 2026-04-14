use anyhow::{Result, anyhow};
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::Ipv4Addr;

use nftables::batch::Batch;
use nftables::expr::{CT, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField};
use nftables::helper;
use nftables::schema::*;
use nftables::stmt;
use nftables::types::*;

const TABLE: &str = "firewall";
const CHAIN: &str = "input";
const SET_BAN: &str = "ban_ip";
const SET_WHITE: &str = "white_ip";

pub struct KernelFirewall;

impl KernelFirewall {
    pub fn new(listen_ports: Vec<u16>) -> Self {
        let fw = Self;
        fw.setup(listen_ports)
            .expect("[ERR] Failed to init nftables");
        fw
    }

    fn apply(batch: Batch) -> Result<()> {
        let nft = batch.to_nftables();
        helper::apply_ruleset(&nft).map_err(|e| anyhow!("{e}"))?;
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

    fn accept_stmt<'a>() -> stmt::Statement<'a> {
        stmt::Statement::Accept(Some(stmt::Accept {}))
    }

    fn limit_stmt<'a>(rate: u64, unit: &str, burst: u32, over: bool) -> stmt::Statement<'a> {
        stmt::Statement::Limit(stmt::Limit {
            rate: rate as u32,
            per: Some(Cow::Owned(unit.to_string())),
            burst: Some(burst),
            inv: Some(over),
            rate_unit: None,
            burst_unit: None,
        })
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

    // ── Setup: table + chain + whitelist + drop policy ──────
    pub fn setup(&self, listen_ports: Vec<u16>) -> Result<()> {
        let mut batch = Batch::new();

        // Delete table if exists to start fresh
        let _ = Self::apply({
            let mut b = Batch::new();
            b.delete(NfListObject::Table(Table {
                family: NfFamily::INet,
                name: Cow::Borrowed(TABLE),
                ..Default::default()
            }));
            b
        });

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
            policy: Some(NfChainPolicy::Drop),
            ..Default::default()
        }));

        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            flags: Some({
                let mut s = HashSet::new();
                s.insert(SetFlag::Interval);
                s
            }),
            ..Default::default()
        })));

        batch.add(NfListObject::Set(Box::new(Set {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            ..Default::default()
        })));

        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("ip", "saddr"),
                stmt::Operator::IN,
                Self::str_expr(&format!("@{SET_WHITE}")),
            ),
            Self::accept_stmt(),
        ])));

        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::Iifname,
                    ..Default::default()
                })),
                stmt::Operator::EQ,
                Self::str_expr("lo"),
            ),
            Self::accept_stmt(),
        ])));

        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                    ..Default::default()
                })),
                stmt::Operator::EQ,
                Self::str_expr("icmp"),
            ),
            Self::accept_stmt(),
        ])));

        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::ct_state(),
                stmt::Operator::EQ,
                Self::str_expr("established"),
            ),
            Self::accept_stmt(),
        ])));

        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::ct_state(),
                stmt::Operator::EQ,
                Self::str_expr("related"),
            ),
            Self::accept_stmt(),
        ])));

        // allow ssh port 22
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("tcp", "dport"),
                stmt::Operator::EQ,
                Expression::Number(22),
            ),
            Self::accept_stmt(),
        ])));

        // drop banned ip
        batch.add(NfListObject::Rule(Self::rule_with(vec![
            Self::match_stmt(
                Self::payload("ip", "saddr"),
                stmt::Operator::IN,
                Self::str_expr(&format!("@{SET_BAN}")),
            ),
            Self::drop_stmt(),
        ])));

        // allow proxy dport ? cai nay la port game open
        for port in listen_ports {
            batch.add(NfListObject::Rule(Self::rule_with(vec![
                Self::match_stmt(
                    Self::payload("tcp", "dport"),
                    stmt::Operator::EQ,
                    Expression::Number(port as u32),
                ),
                Self::accept_stmt(),
            ])));
        }

        Self::apply(batch)?;
        tracing::info!("[OK] KernelFirewall setup: table={TABLE} chain={CHAIN}");
        Ok(())
    }

    // ── Ban IP ──────────────────────────────────────────────
    pub fn ban(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![Self::str_expr(&ip.to_string())]),
        }));
        Self::apply(batch)?;
        tracing::info!("[-] Kernel ban IP: {ip}");
        Ok(())
    }

    pub fn ban_subnet(&self, subnet: &str) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![Self::str_expr(subnet)]),
        }));
        Self::apply(batch)?;
        tracing::info!("[-] Kernel ban SUBNET: {subnet}");
        Ok(())
    }

    pub fn ban_bulk(&self, ips: Vec<Ipv4Addr>) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let mut batch = Batch::new();
        let elements = ips
            .iter()
            .map(|ip| Self::str_expr(&ip.to_string()))
            .collect();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(elements),
        }));
        Self::apply(batch)?;
        tracing::info!("[-] Kernel bulk ban: {} IPs", ips.len());
        Ok(())
    }

    // ── Unban IP ────────────────────────────────────────────
    pub fn unban(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![Self::str_expr(&ip.to_string())]),
        }));
        Self::apply(batch)?;
        tracing::info!("[+] Kernel unban: {ip}");
        Ok(())
    }

    // ── Whitelist IP ──────────────────────────────────────────
    pub fn whitelist(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            elem: Cow::Owned(vec![Self::str_expr(&ip.to_string())]),
        }));
        Self::apply(batch)?;
        tracing::info!("[*] Kernel Whitelist: {ip}");
        Ok(())
    }

    pub fn whitelist_bulk(&self, ips: Vec<Ipv4Addr>) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let mut batch = Batch::new();
        let elements = ips
            .iter()
            .map(|ip| Self::str_expr(&ip.to_string()))
            .collect();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            elem: Cow::Owned(elements),
        }));
        Self::apply(batch)?;
        tracing::info!("[*] Kernel bulk whitelist: {} IPs", ips.len());
        Ok(())
    }

    // ── Remove from Whitelist ─────────────────────────────────
    pub fn unwhitelist(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            elem: Cow::Owned(vec![Self::str_expr(&ip.to_string())]),
        }));
        Self::apply(batch)?;
        tracing::info!("[!] Removed from Whitelist: {ip}");
        Ok(())
    }

    // ── Drop invalid conntrack state ────────────────────────
    pub fn add_invalid_drop(&self) -> Result<()> {
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
        tracing::info!("[OK] Invalid packet drop rule added");
        Ok(())
    }

    // ── SYN flood: drop pure SYN + invalid ct ───────────────
    pub fn add_syn_flood_protection(
        &self,
        listen_ports: Vec<u16>,
        max_syn_per_sec: u32,
    ) -> Result<()> {
        let mut batch = Batch::new();

        // Rule 1: Drop SYN if ct state is invalid
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

        // Rule 2: Rate limit NEW SYN packets for each port
        for port in listen_ports {
            batch.add(NfListObject::Rule(Self::rule_with(vec![
                Self::match_stmt(
                    Self::payload("tcp", "dport"),
                    stmt::Operator::EQ,
                    Expression::Number(port as u32),
                ),
                Self::match_stmt(
                    Self::payload("tcp", "flags"),
                    stmt::Operator::IN,
                    Self::str_expr("syn"),
                ),
                Self::match_stmt(Self::ct_state(), stmt::Operator::EQ, Self::str_expr("new")),
                Self::limit_stmt(max_syn_per_sec as u64, "second", max_syn_per_sec / 2, true),
                Self::drop_stmt(),
            ])));
        }

        Self::apply(batch)?;
        tracing::info!("[OK] Advanced SYN flood protection enabled (limit: {max_syn_per_sec}/s)");
        Ok(())
    }

    // ── Teardown: delete entire table ───────────────────────
    pub fn teardown(&self) -> Result<()> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(TABLE),
            ..Default::default()
        }));
        Self::apply(batch)?;
        tracing::info!("[*] KernelFirewall teardown done");
        Ok(())
    }
}
