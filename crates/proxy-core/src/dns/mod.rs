pub mod fake_ip;
pub mod upstream;
pub mod wire;

pub use fake_ip::{DnsTelemetrySnapshot, FakeIpDnsEngine, FakeIpEntry, PositiveDnsCacheSeed};
