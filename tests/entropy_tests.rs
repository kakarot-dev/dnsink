use dnsink::entropy::EntropyDetector;

#[test]
fn detector_is_constructable_and_stub_returns_false() {
    let detector = EntropyDetector::new(3.5, 20);
    assert!(!detector.is_suspicious("example.com"));
}

#[test]
fn mixed_string_has_higher_entropy_than_repeated() {
    let detector = EntropyDetector::new(3.5, 20);
    let low = detector.shannon_entropy("aaaa");
    let high = detector.shannon_entropy("a1b2c3d4");
    assert!(low < high, "expected {low} < {high}");
}
