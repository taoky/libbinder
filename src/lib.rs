// Reference implementations:
// https://github.com/ustclug/ustcmirror-images/blob/7eab38bceeaa5a6842c626c1674fcc866f869216/yum-sync/binder.c
// https://github.com/pdlan/binder/blob/master/binder.cc

use std::{env, fs::File, io::Read, mem};

use ctor::ctor;
use libc::exit;
use libc_print::libc_eprintln;
use redhook::{hook, real};

struct AddressInfo {
    addr_v4: libc::in_addr,
    addr_v6: libc::in6_addr,
    only_v6: bool,
}

extern "C" {
    fn inet_pton(af: libc::c_int, src: *const libc::c_char, dst: *mut libc::c_void) -> libc::c_int;
}

// Error Enum
#[derive(Debug)]
enum ParseError {
    InvalidIPv6Address,
    InvalidIPv4Address,
}

fn parse_address(ip: &str) -> Result<AddressInfo, ParseError> {
    let mut addr_v4: libc::in_addr = unsafe { mem::zeroed() };
    let mut addr_v6: libc::in6_addr = unsafe { mem::zeroed() };
    if ip.contains(':') {
        if unsafe {
            inet_pton(
                libc::AF_INET6,
                ip.as_ptr() as *const _,
                &mut addr_v6 as *mut _ as *mut _,
            )
        } != 1
        {
            Err(ParseError::InvalidIPv6Address)
        } else {
            Ok(AddressInfo {
                addr_v4,
                addr_v6,
                only_v6: true,
            })
        }
    } else if unsafe {
        inet_pton(
            libc::AF_INET,
            ip.as_ptr() as *const _,
            &mut addr_v4 as *mut _ as *mut _,
        )
    } != 1
    {
        Err(ParseError::InvalidIPv4Address)
    } else {
        // IPv4-mapped IPv6 address
        addr_v6.s6_addr[10] = 0xff;
        addr_v6.s6_addr[11] = 0xff;

        addr_v6.s6_addr[12..16].copy_from_slice(&addr_v4.s_addr.to_be_bytes());

        Ok(AddressInfo {
            addr_v4,
            addr_v6,
            only_v6: false,
        })
    }
}

#[ctor]
static ADDRESS: AddressInfo = {
    let bind_addr = match env::var("BIND_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            libc_eprintln!("BIND_ADDRESS not set, exiting");
            unsafe { exit(1) };
        }
    };
    match parse_address(&bind_addr) {
        Ok(addr) => addr,
        Err(e) => {
            libc_eprintln!("error: failed to parse BIND_ADDRESS {}: {:?}", bind_addr, e);
            unsafe { exit(1) };
        }
    }
};

#[ctor]
static ALLOWLIST: Vec<AddressInfo> = {
    let mut res = Vec::new();
    let mut buf = Vec::with_capacity(4096);
    let f = File::open("/etc/resolv.conf")
        .and_then(|mut f| f.read_to_end(&mut buf))
        .and_then(|_| {
            resolv_conf::Config::parse(&buf)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))
        });
    if let Ok(conf) = f {
        for nameserver in conf.nameservers {
            res.push(match parse_address(&nameserver.to_string()) {
                Ok(addr) => addr,
                Err(_) => {
                    libc_eprintln!("warn: failed to parse nameserver {}", nameserver);
                    continue;
                }
            });
        }
    } else {
        libc_eprintln!("warn: failed to parse /etc/resolv.conf");
    }

    res
};

// #[ctor]
// static IS_BIND_DEBUG: bool = env::var("BIND_DEBUG").is_ok();

fn allowlist_check_v4(addr: libc::sockaddr_in) -> bool {
    for allow_ip in ALLOWLIST.iter() {
        if allow_ip.only_v6 {
            continue;
        }
        if allow_ip.addr_v4.s_addr == addr.sin_addr.s_addr {
            return true;
        }
    }
    false
}

fn allowlist_check_v6(addr: libc::sockaddr_in6) -> bool {
    for allow_ip in ALLOWLIST.iter() {
        if allow_ip.addr_v6.s6_addr == addr.sin6_addr.s6_addr {
            return true;
        }
    }
    false
}

hook! {
    unsafe fn bind(
        sockfd: i32,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t
    ) -> i32 => my_bind {
        // Do nothing if sa_family is neither AF_INET nor AF_INET6
        let sa_family = (*addr).sa_family as i32;
        if sa_family != libc::AF_INET && sa_family != libc::AF_INET6 {
            return real!(bind)(sockfd, addr, addrlen);
        }
        // If getsockopt() failed, don't go further
        let mut optval: libc::c_int = 0;
        let mut optlen: libc::socklen_t = mem::size_of::<libc::c_int>() as _;
        if libc::getsockopt(sockfd, libc::SOL_SOCKET, libc::SO_TYPE, &mut optval as *mut _ as *mut _, &mut optlen as *mut _) != 0 {
            return real!(bind)(sockfd, addr, addrlen);
        }
        // We only want to handle TCP sockets
        if optval != libc::SOCK_STREAM {
            return real!(bind)(sockfd, addr, addrlen);
        }

        let res = match sa_family {
            libc::AF_INET => {
                if ADDRESS.only_v6 {
                    return libc::EACCES;
                }
                let mut inaddr: libc::sockaddr_in = mem::transmute_copy(&*addr);
                inaddr.sin_addr = ADDRESS.addr_v4;
                real!(bind)(sockfd, &inaddr as *const _ as *const _, mem::size_of::<libc::sockaddr_in>() as _)
            }
            libc::AF_INET6 => {
                let mut in6addr: libc::sockaddr_in6 = mem::transmute_copy(&*addr);
                in6addr.sin6_addr = ADDRESS.addr_v6;
                real!(bind)(sockfd, &in6addr as *const _ as *const _, mem::size_of::<libc::sockaddr_in6>() as _)
            }
            _ => unreachable!()
        };

        res
    }
}

hook! {
    unsafe fn connect(
        sockfd: i32,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t
    ) -> i32 => my_connect {
        let sa_family = (*addr).sa_family as i32;
        match sa_family {
            libc::AF_INET => {
                if !allowlist_check_v4(*(addr as *const _ as *const _)) {
                    if ADDRESS.only_v6 {
                        return libc::ECONNREFUSED;
                    }
                    let mut addr4: libc::sockaddr_in = mem::zeroed();
                    addr4.sin_family = libc::AF_INET as _;
                    addr4.sin_addr = ADDRESS.addr_v4;
                    addr4.sin_port = 0;

                    let res = my_bind(sockfd, &addr4 as *const _ as *const _, mem::size_of::<libc::sockaddr_in>() as _);
                    if res != 0 {
                        eprintln!("warn: bind() failed (IPv4) with errno = {:?}", std::io::Error::from_raw_os_error(*libc::__errno_location()));
                    }
                }
            }
            libc::AF_INET6 => {
                if !allowlist_check_v6(*(addr as *const _ as *const _)) {
                    let mut addr6: libc::sockaddr_in6 = mem::zeroed();
                    addr6.sin6_family = libc::AF_INET6 as _;
                    addr6.sin6_addr = ADDRESS.addr_v6;
                    addr6.sin6_port = 0;

                    let res = my_bind(sockfd, &addr6 as *const _ as *const _, mem::size_of::<libc::sockaddr_in6>() as _);
                    if res != 0 {
                        eprintln!("warn: bind() failed (IPv6) with errno = {:?}", std::io::Error::from_raw_os_error(*libc::__errno_location()));
                    }
                }
            }
            _ => {}
        }

        real!(connect)(sockfd, addr, addrlen)
    }
}
