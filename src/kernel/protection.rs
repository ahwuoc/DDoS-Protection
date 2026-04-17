use anyhow::Result;
use nftables::batch::Batch;
use nftables::schema::*;
use nftables::stmt;

use super::KernelFirewall;
use super::helpers::*;

impl KernelFirewall {
    pub fn add_invalid_drop(&self) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(ct_state(), stmt::Operator::EQ, str_expr("invalid")),
            drop_stmt(),
        ])));
        apply(batch)?;
        tracing::info!("[OK] Invalid packet drop rule added");
        Ok(())
    }

    pub fn add_syn_flood_protection(
        &self,
        listen_ports: Vec<u16>,
        max_syn_per_sec: u32,
    ) -> Result<()> {
        let mut batch = Batch::new();

        // Rule 1: Drop invalid SYN packets
        batch.add(NfListObject::Rule(rule_with(vec![
            match_stmt(payload("tcp", "flags"), stmt::Operator::IN, str_expr("syn")),
            match_stmt(ct_state(), stmt::Operator::EQ, str_expr("invalid")),
            drop_stmt(),
        ])));

        // Rule 2: Rate limit NEW SYN packets for ALL game ports using a set
        if !listen_ports.is_empty() {
            let port_exprs = listen_ports
                .iter()
                .map(|&p| nftables::expr::Expression::Number(p as u32))
                .collect();

            batch.add(NfListObject::Rule(rule_with(vec![
                match_stmt(payload("tcp", "dport"), stmt::Operator::IN, set_expr(port_exprs)),
                match_stmt(payload("tcp", "flags"), stmt::Operator::IN, str_expr("syn")),
                match_stmt(ct_state(), stmt::Operator::EQ, str_expr("new")),
                limit_stmt(max_syn_per_sec as u64, "second", max_syn_per_sec / 2, true),
                drop_stmt(),
            ])));
        }

        apply(batch)?;
        tracing::info!("[OK] Advanced SYN flood protection enabled (limit: {max_syn_per_sec}/s)");
        Ok(())
    }
}
