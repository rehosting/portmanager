//! Dynamic-forward + control-socket integration: a live in-process session
//! (agent + client over loopback QUIC), mutated through the real control
//! socket protocol, with persistence checked. Also covers the discovery
//! stream end-to-end against the host namespace.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use portmanager::client::{ForwardSet, conn_slot};
use portmanager::reverse::ReverseSet;
// Only used by the Linux-gated discovery test below.
#[cfg(target_os = "linux")]
use portmanager::config::AutoForwardRule;
use portmanager::control::{self, ControlCtx, Request, Response};
use portmanager::crypto::{self, Identity, Timing};
#[cfg(target_os = "linux")]
use portmanager::discovery;
use portmanager::forward::NsSpec;
use portmanager::supervisor::Status;
use portmanager::{agent, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const TEST_GRACE: Duration = Duration::from_secs(600);

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// In-process agent + connected client; returns the conn for slotting.
async fn session() -> quinn::Connection {
    crypto::init();
    let client_id = Identity::generate().unwrap();
    let agent_id = Identity::generate().unwrap();
    let timing = Timing::default();

    let server_cfg = crypto::server_config(&agent_id, client_id.fingerprint, &timing).unwrap();
    let ep = transport::server_endpoint(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = ep.local_addr().unwrap();
    tokio::spawn(agent::serve_with_grace(ep, TEST_GRACE, None));

    let client_cfg = crypto::client_config(&client_id, agent_id.fingerprint, &timing).unwrap();
    let client_ep = transport::client_endpoint(client_cfg).unwrap();
    transport::connect(&client_ep, addr).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn control_socket_add_drop_list_status() {
    // Unique host key so state/socket files don't collide across test runs.
    let host = format!("testhost-{}", std::process::id());
    let conn = session().await;
    let echo = spawn_echo().await;

    let (_slot_tx, slot_rx) = conn_slot(Some(portmanager::conn::Conn::Quic(conn)));
    let forwards = Arc::new(ForwardSet::new(slot_rx, None));
    let (_status_tx, status_rx) = watch::channel(Status::Connected);

    let (_av_tx, av_rx) = watch::channel("test-agent".to_string());
    let reverse = Arc::new(ReverseSet::new());
    let ctx = ControlCtx {
        host: host.clone(),
        forwards: forwards.clone(),
        reverse: reverse.clone(),
        status: status_rx,
        agent_version: av_rx,
        shutdown: None,
        persist: portmanager::config::PersistTarget::HostState { host: host.clone() },
    };
    let server = tokio::spawn(control::serve(ctx));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // add via the real socket protocol, on an explicit free local port
    let free = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    let spec = format!("127.0.0.1:{}->{}", echo.port(), port);
    let resp = control::request(&host, &Request::Add { spec: spec.clone() })
        .await
        .unwrap();
    assert!(matches!(resp, Response::Ok { .. }), "add failed: {resp:?}");

    // the added forward actually moves bytes
    let mut sock = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    sock.write_all(b"dynamic!").await.unwrap();
    let mut buf = [0u8; 8];
    sock.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"dynamic!");
    drop(sock);

    // list shows it
    let resp = control::request(&host, &Request::List).await.unwrap();
    match resp {
        Response::Forwards {
            entries, reverse, ..
        } => {
            assert_eq!(entries.len(), 1);
            assert!(entries[0].local.ends_with(&format!(":{port}")));
            assert!(reverse.is_empty());
        }
        other => panic!("unexpected list response: {other:?}"),
    }

    // status reports connected + the forward
    let resp = control::request(&host, &Request::Status).await.unwrap();
    match resp {
        Response::StatusIs {
            state,
            agent_version,
            entries,
            reverse,
            default_ns,
        } => {
            assert_eq!(state, "connected");
            assert_eq!(agent_version, "test-agent");
            assert_eq!(entries.len(), 1);
            assert!(reverse.is_empty());
            assert!(default_ns.is_empty(), "no --ns was given for this session");
        }
        other => panic!("unexpected status response: {other:?}"),
    }

    // persistence: the state file remembers the forward
    let state = portmanager::config::load_state(&host).unwrap();
    assert_eq!(state.forwards, vec![spec.clone()]);

    // drop by local port; listener must actually close
    let resp = control::request(
        &host,
        &Request::Drop {
            spec: port.to_string(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }), "drop failed: {resp:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err(),
        "listener should be closed after drop"
    );

    // persistence reflects the drop
    let state = portmanager::config::load_state(&host).unwrap();
    assert!(state.forwards.is_empty());

    server.abort();
    control::cleanup(&host);
    let _ = std::fs::remove_file(portmanager::config::state_path(&host).unwrap());
}

/// Session-default namespace over the real control socket: a later `add` with no
/// `NS@` inherits it, an explicit one doesn't, `portmanager ns` re-points only the
/// inherited forwards, and an unstable (pid) default is never persisted.
#[tokio::test(flavor = "multi_thread")]
async fn control_socket_inherits_and_repoints_the_default_namespace() {
    let host = format!("testns-{}", std::process::id());
    let conn = session().await;

    let (_slot_tx, slot_rx) = conn_slot(Some(portmanager::conn::Conn::Quic(conn)));
    // Launch equivalent of `portmanager --ns pid:4242 <host> ...`. The namespace
    // is only entered when a connection is dialed, so a bogus pid is fine here:
    // this test is about which namespace each forward *carries*.
    let forwards = Arc::new(ForwardSet::new(slot_rx, Some(NsSpec::Pid(4242))));
    let (_status_tx, status_rx) = watch::channel(Status::Connected);
    let (_av_tx, av_rx) = watch::channel("test-agent".to_string());
    let reverse = Arc::new(ReverseSet::new());
    let ctx = ControlCtx {
        host: host.clone(),
        forwards: forwards.clone(),
        reverse: reverse.clone(),
        status: status_rx,
        agent_version: av_rx,
        shutdown: None,
        persist: portmanager::config::PersistTarget::HostState { host: host.clone() },
    };
    let server = tokio::spawn(control::serve(ctx));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let free_port = || async {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let bare_port = free_port().await;
    let explicit_port = free_port().await;

    // `portmanager add <host> 9000->PORT`: no namespace named, so it inherits.
    let resp = control::request(
        &host,
        &Request::Add {
            spec: format!("9000->{bare_port}"),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }), "add failed: {resp:?}");
    // ...while an explicit namespace on the spec wins over the default.
    let resp = control::request(
        &host,
        &Request::Add {
            spec: format!("pid:999@9001->{explicit_port}"),
        },
    )
    .await
    .unwrap();
    assert!(matches!(resp, Response::Ok { .. }), "add failed: {resp:?}");

    let list = forwards.list().await;
    let bare = list.iter().find(|s| s.local.port() == bare_port).unwrap();
    assert_eq!(bare.spec.ns, NsSpec::Pid(4242), "add should inherit --ns");
    assert!(bare.spec.ns_inherited);
    let explicit = list
        .iter()
        .find(|s| s.local.port() == explicit_port)
        .unwrap();
    assert_eq!(explicit.spec.ns, NsSpec::Pid(999));
    assert!(!explicit.spec.ns_inherited);

    // `list` reports the active default so a bare spec's namespace is visible.
    match control::request(&host, &Request::List).await.unwrap() {
        Response::Forwards { default_ns, .. } => assert_eq!(default_ns, "pid:4242"),
        other => panic!("unexpected list response: {other:?}"),
    }

    // Persistence: the inherited forward is remembered *without* the namespace,
    // and a pid default is not remembered at all (it cannot survive a restart).
    let state = portmanager::config::load_state(&host).unwrap();
    assert!(
        state
            .forwards
            .contains(&format!("127.0.0.1:9000->{bare_port}")),
        "inherited forward should persist bare: {:?}",
        state.forwards
    );
    assert!(
        state
            .forwards
            .contains(&format!("pid:999@127.0.0.1:9001->{explicit_port}")),
        "explicit forward should persist in full: {:?}",
        state.forwards
    );
    assert_eq!(state.default_ns, "", "a pid default must not be remembered");

    // Re-point (`portmanager ns <host> podman:web`): the inherited forward moves
    // to the new namespace on the same local port, the explicit one does not.
    let resp = control::request(
        &host,
        &Request::SetNs {
            ns: Some("podman:web".into()),
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(resp, Response::Ok { .. }),
        "ns re-point failed: {resp:?}"
    );
    let list = forwards.list().await;
    let bare = list.iter().find(|s| s.local.port() == bare_port).unwrap();
    assert_eq!(bare.spec.ns, NsSpec::Podman("web".into()));
    let explicit = list
        .iter()
        .find(|s| s.local.port() == explicit_port)
        .unwrap();
    assert_eq!(explicit.spec.ns, NsSpec::Pid(999));

    // A container-name default *is* re-resolvable, so it is remembered.
    let state = portmanager::config::load_state(&host).unwrap();
    assert_eq!(state.default_ns, "podman:web");

    server.abort();
    control::cleanup(&host);
    let _ = std::fs::remove_file(portmanager::config::state_path(&host).unwrap());
}

/// Discovery end-to-end against the host namespace: a listener that starts
/// AFTER the session is up gets auto-forwarded per a matching rule.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn discovery_autoforwards_new_listener() {
    let host = format!("testdisc-{}", std::process::id());
    let conn = session().await;

    let (slot_tx, slot_rx) = conn_slot(Some(portmanager::conn::Conn::Quic(conn)));
    let forwards = Arc::new(ForwardSet::new(slot_rx.clone(), None));

    // Start a listener *after* session start, then a rule that matches it.
    let echo = spawn_echo().await;
    let rules = vec![AutoForwardRule {
        ns: "host".into(),
        ports: echo.port().to_string(),
        local: "auto".into(),
    }];

    let watcher = tokio::spawn(discovery::watch(
        host.clone(),
        slot_rx,
        forwards.clone(),
        rules,
        None,
    ));

    // Wait for the scanner to find it and the watcher to bind it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let bound = loop {
        let list = forwards.list().await;
        if let Some(s) = list.first() {
            assert_eq!(s.spec.remote_port, echo.port());
            break s.local;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("discovery never auto-forwarded the listener");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    // The auto-forward moves bytes.
    let mut sock = TcpStream::connect(bound).await.unwrap();
    sock.write_all(b"auto").await.unwrap();
    let mut buf = [0u8; 4];
    sock.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"auto");

    // Stable assignment was persisted.
    let state = portmanager::config::load_state(&host).unwrap();
    let key = portmanager::config::HostState::assignment_key("", echo.port());
    assert_eq!(state.assignments.get(&key).copied(), Some(bound.port()));

    watcher.abort();
    drop(slot_tx);
    let _ = std::fs::remove_file(portmanager::config::state_path(&host).unwrap());
}
