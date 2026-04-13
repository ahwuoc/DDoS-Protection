use std::ffi::CString;
use std::net::Ipv4Addr;

use nftnl::expr::{Bitwise, Cmp, CmpOp};
use nftnl::set::Set;
use nftnl::{Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table, nft_expr};

const TABLE_NAME: &str = "firewall";
const CHAIN_NAME: &str = "input";
const SET_BAN: &str = "ban_ip";

// TCP header byte offset 13 = flags byte
// Bit: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
// SYN=0x02, ACK=0x10 → mask SYN|ACK = 0x12
const TCP_FLAGS_OFFSET: u32 = 13;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_SYN_ACK_MASK: u8 = 0x12;
const IPPROTO_TCP: u8 = 0x06;

pub struct KernelFirewall {
    pub table_name: CString,
}

impl KernelFirewall {
    pub fn new() -> Self {
        let fw = Self {
            table_name: CString::new(TABLE_NAME).unwrap(),
        };
        fw.setup().expect("❌ Không thể khởi tạo netfilter table");
        fw
    }

    /// Khởi tạo table + chain + ban_ip set + rule drop banned IP
    pub fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();

        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Add);

        let mut chain = Chain::new(&CString::new(CHAIN_NAME).unwrap(), &table);
        chain.set_hook(nftnl::Hook::In, 0);
        chain.set_policy(nftnl::Policy::Accept);
        batch.add(&chain, nftnl::MsgType::Add);

        let set = Set::<Ipv4Addr>::new(
            &CString::new(SET_BAN).unwrap(),
            0,
            &table,
            ProtoFamily::Inet,
        );
        batch.add(&set, nftnl::MsgType::Add);

        // Rule: ip saddr ∈ ban_ip → DROP
        let mut rule = Rule::new(&chain);
        rule.add_expr(&nft_expr!(meta nfproto));
        rule.add_expr(&nft_expr!(payload ipv4 saddr));
        rule.add_expr(&nft_expr!(lookup & set));
        rule.add_expr(&nft_expr!(verdict drop));
        batch.add(&rule, nftnl::MsgType::Add);

        send_batch(batch.finalize())?;
        tracing::info!("✅ KernelFirewall setup: table={TABLE_NAME} chain={CHAIN_NAME}");
        Ok(())
    }

    /// Thêm IP vào kernel set → kernel DROP ngay tại netfilter
    pub fn ban(&self, ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        let mut set = Set::<Ipv4Addr>::new(
            &CString::new(SET_BAN).unwrap(),
            0,
            &table,
            ProtoFamily::Inet,
        );
        set.add(&ip);
        batch.add_iter(set.elems_iter(), nftnl::MsgType::Add);
        send_batch(batch.finalize())?;
        tracing::info!("🚫 Kernel ban: {ip}");
        Ok(())
    }

    pub fn unban(&self, ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        let mut set = Set::<Ipv4Addr>::new(
            &CString::new(SET_BAN).unwrap(),
            0,
            &table,
            ProtoFamily::Inet,
        );
        set.add(&ip);
        batch.add_iter(set.elems_iter(), nftnl::MsgType::Del);
        send_batch(batch.finalize())?;
        tracing::info!("✅ Kernel unban: {ip}");
        Ok(())
    }

    pub fn add_syn_flood_protection(
        &self,
        _max_syn_per_sec: u32, // dùng cho logging, rate limit thực tế ở tầng userspace
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        let chain = Chain::new(&CString::new(CHAIN_NAME).unwrap(), &table);

        let mut rule = Rule::new(&chain);

        rule.add_expr(&nft_expr!(payload_raw nh 9, 1));
        rule.add_expr(&Cmp::new(CmpOp::Eq, IPPROTO_TCP));
        rule.add_expr(&nft_expr!(payload_raw th TCP_FLAGS_OFFSET, 1));
        rule.add_expr(&Bitwise::new(&[TCP_SYN_ACK_MASK][..], &[0x00u8][..]));
        rule.add_expr(&Cmp::new(CmpOp::Eq, TCP_FLAG_SYN));
        rule.add_expr(&nft_expr!(ct state));
        rule.add_expr(&nft_expr!(bitwise mask 0x01u32, xor 0x00u32));
        rule.add_expr(&nft_expr!(cmp != 0x00u32));
        rule.add_expr(&nft_expr!(verdict drop));

        batch.add(&rule, nftnl::MsgType::Add);
        send_batch(batch.finalize())?;
        tracing::info!("✅ SYN invalid-state drop rule added");
        Ok(())
    }

    pub fn add_invalid_drop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        let chain = Chain::new(&CString::new(CHAIN_NAME).unwrap(), &table);

        let mut rule = Rule::new(&chain);
        rule.add_expr(&nft_expr!(ct state));
        rule.add_expr(&nft_expr!(bitwise mask 0x01u32, xor 0x00u32));
        rule.add_expr(&nft_expr!(cmp != 0x00u32));
        rule.add_expr(&nft_expr!(verdict drop));
        batch.add(&rule, nftnl::MsgType::Add);

        send_batch(batch.finalize())?;
        tracing::info!("✅ Invalid packet drop rule added");
        Ok(())
    }

    pub fn add_allow_only_tcp_port(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        let chain = Chain::new(&CString::new(CHAIN_NAME).unwrap(), &table);

        let mut rule_proto = Rule::new(&chain);
        rule_proto.add_expr(&nft_expr!(payload_raw nh 9, 1));
        rule_proto.add_expr(&Cmp::new(CmpOp::Neq, IPPROTO_TCP));
        rule_proto.add_expr(&nft_expr!(verdict drop));
        batch.add(&rule_proto, nftnl::MsgType::Add);

        let mut rule_port = Rule::new(&chain);
        rule_port.add_expr(&nft_expr!(payload_raw th 2, 2));
        rule_port.add_expr(&Cmp::new(CmpOp::Neq, port.to_be()));
        rule_port.add_expr(&nft_expr!(verdict drop));
        batch.add(&rule_port, nftnl::MsgType::Add);

        send_batch(batch.finalize())?;
        tracing::info!("✅ Allow only TCP port {port}");
        Ok(())
    }

    /// Cleanup toàn bộ table khi shutdown
    pub fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = Batch::new();
        let table = Table::new(&self.table_name, ProtoFamily::Inet);
        batch.add(&table, nftnl::MsgType::Del);
        send_batch(batch.finalize())?;
        tracing::info!("🧹 KernelFirewall teardown xong");
        Ok(())
    }
}

/// Gửi nftnl batch xuống kernel qua netlink socket — không CLI
fn send_batch(batch: FinalizedBatch) -> Result<(), Box<dyn std::error::Error>> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    socket.send_all(&batch)?;
    Ok(())
}
