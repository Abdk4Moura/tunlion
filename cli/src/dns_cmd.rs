//! `tunlion dns query <name> [--type A|AAAA|PTR]`: ask the running daemon's mesh
//! name responder over the control socket.
//!
//! It answers through the SAME code path a packet to the responder address
//! takes (encode, `mesh_dns::respond`, decode), so it shows what any resolver
//! pointed at `fdf1:1af7:c30d::53` would get, and it works with no OS DNS
//! configuration at all, including on a userspace daemon where no packet can
//! reach the responder.

use anyhow::{anyhow, bail, Result};
use serde_json::json;

use crate::cli_def::DnsAction;
use crate::mesh_dns;
use crate::ui;

pub(crate) fn dns_cmd(action: DnsAction) -> Result<()> {
    match action {
        DnsAction::Query { name, qtype } => query(&name, qtype.as_deref()),
    }
}

/// What to ask for a user-typed `name`: an address becomes its reverse name
/// (PTR by default), a bare device name gets the mesh suffix, and anything
/// else is asked verbatim (a name outside our zones is REFUSED, which is the
/// point: the responder never forwards).
pub(crate) fn question_for(name: &str, qtype: Option<&str>) -> Result<(String, u16)> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        bail!("name a device, e.g. `tunlion dns query laptop`");
    }
    let ty = |default: u16| -> Result<u16> {
        match qtype {
            None => Ok(default),
            Some(t) => mesh_dns::parse_type(t)
                .ok_or_else(|| anyhow!("unknown record type '{t}': use A, AAAA or PTR")),
        }
    };
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return Ok((mesh_dns::reverse_name(ip), ty(mesh_dns::TYPE_PTR)?));
    }
    let qname = if name.contains('.') { name.to_string() } else { format!("{name}.{}", mesh_dns::SUFFIX) };
    // ANY by default: both families in one answer, which is what a person asking
    // "what is laptop" wants to see.
    Ok((qname, ty(mesh_dns::TYPE_ANY)?))
}

fn query(name: &str, qtype: Option<&str>) -> Result<()> {
    let (qname, ty) = question_for(name, qtype)?;
    let Some(v) = crate::ctl::dns_request(&json!({ "op": "dns-query", "name": qname, "qtype": ty })) else {
        bail!(
            "no daemon answered: start one with `tunlion up` (the responder lives in the daemon, \
             with its L3 overlay on)"
        );
    };
    let rcode = v["rcode"].as_str().unwrap_or("?");
    let answers = v["answers"].as_array().cloned().unwrap_or_default();
    // Answers on stdout, one per line, like `dig +short`: this is the output a
    // script captures. Everything else is a human aside on the ui channel.
    for a in &answers {
        if let Some(d) = a["data"].as_str() {
            println!("{d}");
        }
    }
    match rcode {
        "NOERROR" if answers.is_empty() => {
            ui::say(&format!("{qname}: exists, but has no {} record", mesh_dns::type_name(ty)));
            Ok(())
        }
        "NOERROR" => Ok(()),
        "NXDOMAIN" => bail!(
            "{qname}: no such device (NXDOMAIN). A name two devices share resolves to neither; \
             `tunlion status` lists each one's alias"
        ),
        "REFUSED" => bail!("{qname}: REFUSED, not a mesh name (the responder answers only .{} and the overlay's reverse zones, and never forwards)", mesh_dns::SUFFIX),
        other => bail!("{qname}: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::question_for;
    use crate::mesh_dns::{TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_PTR};

    #[test]
    fn a_bare_name_gets_the_suffix_and_an_address_its_reverse_name() {
        assert_eq!(question_for("laptop", None).unwrap(), ("laptop.mesh".into(), TYPE_ANY));
        assert_eq!(question_for("laptop.mesh.", Some("aaaa")).unwrap(), ("laptop.mesh".into(), TYPE_AAAA));
        assert_eq!(question_for("Laptop", Some("A")).unwrap().1, TYPE_A);
        let (n, t) = question_for("198.18.1.2", None).unwrap();
        assert_eq!((n.as_str(), t), ("2.1.18.198.in-addr.arpa", TYPE_PTR));
        assert!(question_for("fdf1:1af7:c30d::1", None).unwrap().0.ends_with(".d.0.3.c.7.f.a.1.1.f.d.f.ip6.arpa"));
        assert_eq!(question_for("example.com", None).unwrap().0, "example.com");
        assert!(question_for("laptop", Some("bogus")).is_err());
        assert!(question_for("  ", None).is_err());
    }
}
