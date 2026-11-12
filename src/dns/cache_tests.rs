//! Pure cache-clock samples: never change or pause the operating system clock.
use super::*;

fn base() -> CacheTime {
    CacheTime {
        monotonic: Instant::now(),
        wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
    }
}

fn sample(base: CacheTime, monotonic_seconds: u64, wall_seconds: u64) -> CacheTime {
    CacheTime {
        monotonic: base.monotonic + Duration::from_secs(monotonic_seconds),
        wall: base.wall + Duration::from_secs(wall_seconds),
    }
}

fn addresses() -> Vec<Ipv4Addr> {
    vec![Ipv4Addr::new(10, 77, 0, 42)]
}

#[test]
fn either_clock_can_expire_a_cached_answer() {
    let now = base();
    for later in [
        sample(now, 1, 3601),
        sample(now, 300, 1),
        sample(now, 1, 300),
    ] {
        let mut cache = CacheState::default();
        cache.insert("service.corp.example".into(), addresses(), 300, now);
        assert_eq!(
            cache.get("service.corp.example", sample(now, 1, 1)),
            Some(addresses())
        );
        assert!(cache.get("service.corp.example", later).is_none());
        assert!(cache.entries.is_empty());
    }
}

#[test]
fn an_observed_wall_clock_rollback_invalidates_all_old_entries() {
    let now = base();
    let mut cache = CacheState::default();
    cache.insert("one".into(), addresses(), 300, now);
    cache.insert("two".into(), addresses(), 300, now);
    assert!(cache.get("one", sample(now, 2, 2)).is_some());
    assert!(cache.get("one", sample(now, 3, 1)).is_none());
    assert!(cache.entries.is_empty());
    // Only a fresh network result can populate the cache after that observation.
    cache.insert("fresh".into(), addresses(), 60, sample(now, 4, 2));
    assert!(cache.get("two", sample(now, 5, 3)).is_none());
    assert!(cache.get("fresh", sample(now, 5, 3)).is_some());
}

#[test]
fn a_full_cache_evicts_one_entry_by_the_shorter_remaining_clock() {
    let now = base();
    let mut cache = CacheState::default();
    cache.insert("wall-limited".into(), addresses(), 30, now);
    cache.insert("mono-limited".into(), addresses(), 15, sample(now, 1, 20));
    let later = sample(now, 2, 29);
    for index in 0..CACHE_ENTRIES - 2 {
        cache.insert(format!("other-{index}"), addresses(), 300, later);
    }
    assert_eq!(cache.entries.len(), CACHE_ENTRIES);
    assert_eq!(
        cache.entries["wall-limited"].remaining(later),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        cache.entries["mono-limited"].remaining(later),
        Some(Duration::from_secs(6))
    );
    cache.insert("new".into(), addresses(), 300, later);
    assert_eq!(cache.entries.len(), CACHE_ENTRIES);
    assert!(!cache.entries.contains_key("wall-limited"));
    assert!(cache.entries.contains_key("mono-limited"));
    assert!(
        (0..CACHE_ENTRIES - 2).all(|index| cache.entries.contains_key(&format!("other-{index}")))
    );
    cache.insert("new".into(), addresses(), 300, later);
    assert_eq!(
        cache.entries.len(),
        CACHE_ENTRIES,
        "updating an existing key must not evict another entry"
    );
}

#[test]
fn ttl_is_clamped_and_zero_ttl_invalidates_an_older_copy() {
    let now = base();
    let mut cache = CacheState::default();
    cache.insert("service".into(), addresses(), u32::MAX, now);
    assert_eq!(
        cache.entries["service"].remaining(now),
        Some(Duration::from_secs(300))
    );
    cache.insert("service".into(), addresses(), 0, sample(now, 1, 1));
    assert!(cache.get("service", sample(now, 2, 2)).is_none());
}
