import pytest
from backend.services.synthetic_data import synthetic_generator


@pytest.mark.parametrize("scenario", ["benign", "ddos", "portscan", "bruteforce", "sqli", "lateral_movement"])
def test_synthetic_single_event_scenarios(scenario):
    event = synthetic_generator.generate_single_event(attack_type=scenario)
    
    assert "id" in event
    assert "source_ip" in event
    assert "dest_ip" in event
    assert "dest_port" in event
    assert 0 <= event["dest_port"] <= 65535
    assert event["protocol"] in ["TCP", "UDP"]
    assert event["packet_count"] >= 1
    assert event["dataset_source"] == "synthetic"
    assert "raw_features" in event
    assert event["raw_features"]["attack_type"] == scenario


def test_synthetic_batch_generation():
    count = 50
    batch = synthetic_generator.generate_batch(count=count, scenario="mixed")
    
    assert len(batch) == count
    labels = {e["raw_features"]["ground_truth_label"] for e in batch}
    # In a mixed batch of 50, multiple distinct labels should exist
    assert len(labels) >= 2


def test_bruteforce_characteristics():
    event = synthetic_generator.generate_single_event(attack_type="bruteforce")
    assert event["failed_login_count"] >= 5
    assert event["dest_port"] in [22, 8080]


def test_portscan_characteristics():
    event = synthetic_generator.generate_single_event(attack_type="portscan")
    assert event["connection_rate"] >= 10.0
    assert event["port_diversity"] >= 10
