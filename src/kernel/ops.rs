use anyhow::Result;
use std::borrow::Cow;
use std::net::Ipv4Addr;
use nftables::batch::Batch;
use nftables::schema::*;
use nftables::types::NfFamily;

use super::KernelFirewall;
use super::constants::*;
use super::helpers::*;

impl KernelFirewall {
    pub fn ban(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![str_expr(&ip.to_string())]),
        }));
        apply(batch)?;
        tracing::info!("[-] Kernel ban IP: {ip}");
        Ok(())
    }

    pub fn ban_subnet(&self, subnet: &str) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![str_expr(subnet)]),
        }));
        apply(batch)?;
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
            .map(|ip| str_expr(&ip.to_string()))
            .collect();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(elements),
        }));
        apply(batch)?;
        tracing::info!("[-] Kernel bulk ban: {} IPs", ips.len());
        Ok(())
    }

    pub fn unban(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_BAN),
            elem: Cow::Owned(vec![str_expr(&ip.to_string())]),
        }));
        apply(batch)?;
        tracing::info!("[+] Kernel unban: {ip}");
        Ok(())
    }

    pub fn whitelist(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            elem: Cow::Owned(vec![str_expr(&ip.to_string())]),
        }));
        apply(batch)?;
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
            .map(|ip| str_expr(&ip.to_string()))
            .collect();
        batch.add(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            elem: Cow::Owned(elements),
        }));
        apply(batch)?;
        tracing::info!("[*] Kernel bulk whitelist: {} IPs", ips.len());
        Ok(())
    }

    pub fn unwhitelist(&self, ip: Ipv4Addr) -> Result<()> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Element(Element {
            family: NfFamily::INet,
            table: Cow::Borrowed(TABLE),
            name: Cow::Borrowed(SET_WHITE),
            elem: Cow::Owned(vec![str_expr(&ip.to_string())]),
        }));
        apply(batch)?;
        tracing::info!("[!] Removed from Whitelist: {ip}");
        Ok(())
    }
}
