import random
import uuid
from datetime import datetime, timedelta
from typing import Literal


AttackType = Literal["benign", "ddos", "portscan", "bruteforce", "sqli", "lateral_movement"]


class SyntheticDataGenerator:
    """
    Generates statistically realistic cybersecurity network flow events
    for both benign enterprise traffic and various attack profiles.
    """

    INTERNAL_IPS = [f"10.0.1.{i}" for i in range(10, 50)]
    EXTERNAL_IPS = [f"198.51.100.{i}" for i in range(1, 254)]
    ATTACKER_IPS = [f"203.0.113.{i}" for i in range(10, 20)]
    SERVER_IPS = ["10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40"]

    COMMON_PORTS = [80, 443, 22, 53, 3306, 5432, 8080, 8443]

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate_single_event(
        self,
        attack_type: AttackType = "benign",
        base_time: datetime | None = None,
    ) -> dict:
        event_time = base_time or datetime.utcnow()

        if attack_type == "benign":
            src_ip = self.rng.choice(self.INTERNAL_IPS)
            dst_ip = self.rng.choice(self.SERVER_IPS)
            dst_port = self.rng.choice([80, 443, 53, 8080])
            src_port = self.rng.randint(32768, 61000)
            protocol = "TCP" if dst_port != 53 else "UDP"
            packet_count = self.rng.randint(5, 120)
            bytes_sent = packet_count * self.rng.randint(60, 400)
            bytes_received = packet_count * self.rng.randint(150, 1400)
            connection_rate = self.rng.uniform(0.1, 2.5)
            failed_login_count = 0 if self.rng.random() > 0.05 else 1
            session_duration = self.rng.uniform(0.5, 45.0)
            port_diversity = 1
            label = "BENIGN"

        elif attack_type == "portscan":
            src_ip = self.rng.choice(self.ATTACKER_IPS)
            dst_ip = self.rng.choice(self.SERVER_IPS)
            dst_port = self.rng.randint(1, 1024)
            src_port = self.rng.randint(40000, 60000)
            protocol = "TCP"
            packet_count = self.rng.randint(1, 3)
            bytes_sent = packet_count * 64
            bytes_received = 0 if self.rng.random() > 0.3 else 64
            connection_rate = self.rng.uniform(20.0, 150.0)
            failed_login_count = 0
            session_duration = self.rng.uniform(0.01, 0.2)
            port_diversity = self.rng.randint(25, 200)
            label = "PORTSCAN"

        elif attack_type == "bruteforce":
            src_ip = self.rng.choice(self.ATTACKER_IPS)
            dst_ip = self.rng.choice(self.SERVER_IPS)
            dst_port = 22 if self.rng.random() > 0.3 else 8080
            src_port = self.rng.randint(30000, 65000)
            protocol = "TCP"
            packet_count = self.rng.randint(15, 60)
            bytes_sent = self.rng.randint(800, 3000)
            bytes_received = self.rng.randint(500, 2500)
            connection_rate = self.rng.uniform(5.0, 30.0)
            failed_login_count = self.rng.randint(5, 50)
            session_duration = self.rng.uniform(1.0, 10.0)
            port_diversity = 1
            label = "BRUTEFORCE"

        elif attack_type == "ddos":
            src_ip = self.rng.choice(self.ATTACKER_IPS)
            dst_ip = self.rng.choice(self.SERVER_IPS)
            dst_port = self.rng.choice([80, 443])
            src_port = self.rng.randint(1024, 65535)
            protocol = "TCP"
            packet_count = self.rng.randint(500, 10000)
            bytes_sent = packet_count * self.rng.randint(500, 1500)
            bytes_received = self.rng.randint(0, 500)
            connection_rate = self.rng.uniform(100.0, 1500.0)
            failed_login_count = 0
            session_duration = self.rng.uniform(0.1, 5.0)
            port_diversity = 1
            label = "DDOS"

        elif attack_type == "sqli":
            src_ip = self.rng.choice(self.ATTACKER_IPS)
            dst_ip = self.rng.choice(self.SERVER_IPS)
            dst_port = self.rng.choice([80, 443, 8080])
            src_port = self.rng.randint(30000, 60000)
            protocol = "TCP"
            packet_count = self.rng.randint(20, 100)
            bytes_sent = self.rng.randint(3000, 15000)  # Large payloads
            bytes_received = self.rng.randint(800, 8000)
            connection_rate = self.rng.uniform(1.0, 10.0)
            failed_login_count = self.rng.randint(0, 3)
            session_duration = self.rng.uniform(2.0, 20.0)
            port_diversity = 1
            label = "SQLI"

        elif attack_type == "lateral_movement":
            src_ip = self.rng.choice(self.INTERNAL_IPS)
            dst_ip = self.rng.choice(self.SERVER_IPS)
            dst_port = self.rng.choice([445, 3389, 22, 5985])
            src_port = self.rng.randint(49152, 65535)
            protocol = "TCP"
            packet_count = self.rng.randint(40, 250)
            bytes_sent = self.rng.randint(2000, 20000)
            bytes_received = self.rng.randint(5000, 40000)
            connection_rate = self.rng.uniform(3.0, 15.0)
            failed_login_count = self.rng.randint(1, 8)
            session_duration = self.rng.uniform(5.0, 60.0)
            port_diversity = self.rng.randint(2, 6)
            label = "LATERAL_MOVEMENT"

        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

        return {
            "id": str(uuid.uuid4()),
            "event_time": event_time.isoformat(),
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "connection_rate": connection_rate,
            "failed_login_count": failed_login_count,
            "session_duration": session_duration,
            "port_diversity": port_diversity,
            "dataset_source": "synthetic",
            "raw_features": {
                "ground_truth_label": label,
                "attack_type": attack_type,
            }
        }

    def generate_batch(
        self,
        count: int = 100,
        scenario: str = "mixed",
    ) -> list[dict]:
        """
        Generate a batch of network events.
        Scenarios: 'mixed', 'ddos', 'portscan', 'bruteforce', 'sqli', 'benign'
        """
        events = []
        now = datetime.utcnow()

        for i in range(count):
            event_time = now - timedelta(seconds=(count - i) * 2)

            if scenario == "mixed":
                # 60% benign, 40% attacks distributed
                roll = self.rng.random()
                if roll < 0.60:
                    atype = "benign"
                elif roll < 0.70:
                    atype = "portscan"
                elif roll < 0.80:
                    atype = "bruteforce"
                elif roll < 0.90:
                    atype = "ddos"
                elif roll < 0.95:
                    atype = "sqli"
                else:
                    atype = "lateral_movement"
            else:
                atype = scenario

            event = self.generate_single_event(attack_type=atype, base_time=event_time)
            events.append(event)

        return events


synthetic_generator = SyntheticDataGenerator()
