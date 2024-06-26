#![no_std]
#![no_main]

use core::mem;

// use aya_ebpf::{bindings::xdp_action, macros::xdp, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map(name = "ALLOWLIST")] //
static mut ALLOWLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

fn allow_ip(address: u32) -> bool {
    unsafe { ALLOWLIST.get(&address).is_some() }
}

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_firewall(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0).unwrap() };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN).unwrap() };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let action = if allow_ip(source) {
        xdp_action::XDP_PASS
    } else {
        xdp_action::XDP_DROP
    };
    info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);

    Ok(action)

}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}