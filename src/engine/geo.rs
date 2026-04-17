use crate::tracker::*;
use super::ConnectionTracker;
use std::net::IpAddr;

impl ConnectionTracker {

    pub fn get_ip_info(&self, ip: IpAddr) -> IpInfo {
        let mut country = "??".to_string();
        let mut org = "Unknown".to_string();
        if let Some(ref r) = self.country_reader {
            if let Ok(c) = r.lookup::<maxminddb::geoip2::Country>(ip) {
                country = c
                    .country
                    .and_then(|co| co.iso_code)
                    .unwrap_or("??")
                    .to_string();
            }
        }
        if let Some(ref r) = self.asn_reader {
            if let Ok(a) = r.lookup::<maxminddb::geoip2::Asn>(ip) {
                org = a
                    .autonomous_system_organization
                    .unwrap_or("Unknown")
                    .to_string();
            }
        }
        IpInfo {
            country,
            asn_org: org,
        }
    }
}
