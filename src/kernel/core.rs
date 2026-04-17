use anyhow::Result;
use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression};
use nftables::schema::*;
use nftables::stmt;
use nftables::types::*;
use std::borrow::Cow;
use std::collections::HashSet;

use super::KernelFirewall;
use super::constants::*;
use super::helpers::*;

impl KernelFirewall {
    pub fn new(listen_ports: Vec<u16>) -> Self {
        let fw = Self;
        fw.setup(listen_ports)
            .expect("[ERR] Failed to init nftables");
        fw
    }

    pub fn setup(&self, listen_ports: Vec<u16>) -> Result<()> {
        let mut batch = Batch::new();

        let _ = apply({
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

        // NEW: PREROUTING chain for early dropping (Pre-Conntrack)
        batch.add(NfListObject::Chain(Chain {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed("early_drop"),
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Prerouting),
            prio: Some(-300), // Very early priority
            policy: Some(NfChainPolicy::Accept),
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

        // --- PREROUTING RULES (EARLY DROP) ---

        // DROP banned IPs immediately in prerouting
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            chain: Cow::Borrowed("early_drop"),
            expr: Cow::Owned(vec![
                match_stmt(
                    payload("ip", "saddr"),
                    stmt::Operator::IN,
                    str_expr(&format!("@{SET_BAN}")),
                ),
                drop_stmt(),
            ]),
            ..Default::default()
        }));

        // Whitelist IP early
        batch.add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            chain: Cow::Borrowed("early_drop"),
            expr: Cow::Owned(vec![
                match_stmt(
                    payload("ip", "saddr"),
                    stmt::Operator::IN,
                    str_expr(&format!("@{SET_WHITE}")),
                ),
                accept_stmt(),
            ]),
            ..Default::default()
        }));

        // --- INPUT RULES ---

        // FAST PATH: established/related
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(ct_state(), stmt::Operator::EQ, str_expr("established")),
            accept_stmt(),
        ])));

        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(ct_state(), stmt::Operator::EQ, str_expr("related")),
            accept_stmt(),
        ])));

        // DROP invalid conntrack
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(ct_state(), stmt::Operator::EQ, str_expr("invalid")),
            drop_stmt(),
        ])));

        // Loopback
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(
                Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::Iifname,
                    ..Default::default()
                })),
                stmt::Operator::EQ,
                str_expr("lo"),
            ),
            accept_stmt(),
        ])));

        // ICMP
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(
                Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                    ..Default::default()
                })),
                stmt::Operator::EQ,
                str_expr("icmp"),
            ),
            accept_stmt(),
        ])));

        // SSH
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(
                payload("tcp", "dport"),
                stmt::Operator::EQ,
                nftables::expr::Expression::Number(22),
            ),
            accept_stmt(),
        ])));

        // Game ports: optimized using a set
        if !listen_ports.is_empty() {
            let port_exprs = listen_ports
                .iter()
                .map(|&p| nftables::expr::Expression::Number(p as u32))
                .collect();
            batch.add(NfListObject::Rule(rule_with(vec![
                match_stmt(payload("tcp", "dport"), stmt::Operator::IN, set_expr(port_exprs)),
                accept_stmt(),
            ])));
        }

        apply(batch)?;
        tracing::info!("[OK] KernelFirewall setup: table={TABLE} chain={CHAIN}");
        Ok(())
    }

    pub fn teardown(&self) -> Result<()> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(TABLE),
            ..Default::default()
        }));
        apply(batch)?;
        tracing::info!("[*] KernelFirewall teardown done");
        Ok(())
    }
}
