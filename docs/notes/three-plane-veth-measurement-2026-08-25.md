# Pinned-Path Throughput Measurement

## Question

The earlier A-to-C comparison mixed transport plane with route selection: one
path used the public interface while another used Tailscale IPv6. These numbers
remove that confound by using one host, two Linux network namespaces, and one
veth underlay (`10.77.0.0/24`).

## Result

`iperf3` ran for ten seconds from node A to node B.

| Plane | Throughput |
| --- | ---: |
| Raw veth control | 18,096.6 Mbps |
| Kernel WireGuard | 1,356.8 Mbps |

Both arms used the same `two-nodes` namespace topology and veth path. The raw
control establishes the underlay capacity; the WireGuard arm measures kernel
WireGuard on that exact path.

## Provenance

The lab checkout that executed the raw and WireGuard arms was
`/root/stunning-tribble` at detached commit `8097771`. The lab topology and the
kernel WireGuard datapath, not a Filament binary, produced those two arms.

A fresh current-main Filament binary was built separately at commit `972b1c0`:

```
ac1f9e423b5b1d56ed67544b08aebfb00485e24d10038dd3da12f0450667e364
```

## Filament L3 Arm

No comparable Filament L3 result exists on current main. Commit `9b04758`
deliberately removed the `serve-tun` command surface and its compatibility
shim. The L3 machinery remains in `cli/src/direct.rs`, but current main exposes
no supported CLI entry point for the lab to start it. The lab peers therefore
exit with `unknown command or device 'serve-tun'`.

This is a product-surface finding, not a measurement failure. Reintroducing an
older command or invoking a private path would make the third arm incomparable
to the current-main controls, so it was not measured.
