from dataclasses import dataclass


@dataclass(frozen=True)
class HoneypotResponse:
    service_type: str
    response_text: str
    canary_triggered: bool


class HoneypotService:
    service_type = "digital_twin"

    def handle(self, input_text: str) -> HoneypotResponse:
        return HoneypotResponse(
            service_type=self.service_type,
            response_text=self.response_text(input_text),
            canary_triggered="canary" in input_text.lower(),
        )

    def response_text(self, input_text: str) -> str:
        raise NotImplementedError


class FakeSSHService(HoneypotService):
    service_type = "ssh"

    def response_text(self, input_text: str) -> str:
        return "fake-shell$ command accepted; output recorded"


class FakeWebService(HoneypotService):
    service_type = "web"

    def response_text(self, input_text: str) -> str:
        return "HTTP/1.1 200 OK\n<html><body>Internal application</body></html>"


class FakeDBService(HoneypotService):
    service_type = "db"

    def response_text(self, input_text: str) -> str:
        return "database=> query accepted; result queued"


class FakeCredentialService(HoneypotService):
    service_type = "credentials"

    def response_text(self, input_text: str) -> str:
        return "credential validation pending; audit token issued"


class DigitalTwinService(HoneypotService):
    service_type = "digital_twin"

    def response_text(self, input_text: str) -> str:
        return "digital-twin request accepted; interaction recorded"


class HoneypotRegistry:
    def __init__(self):
        services = (
            FakeSSHService(),
            FakeWebService(),
            FakeDBService(),
            FakeCredentialService(),
            DigitalTwinService(),
        )
        self.services = {service.service_type: service for service in services}

    def handle(self, service_type: str, input_text: str) -> HoneypotResponse:
        service = self.services.get(service_type.lower())
        if service is None:
            raise ValueError(f"Unsupported deception service: {service_type}")
        return service.handle(input_text)

    def status(self) -> dict:
        return {
            "status": "SIMULATOR_READY",
            "isolated": True,
            "services": {
                service_type: "ONLINE" for service_type in self.services
            },
        }


honeypot_registry = HoneypotRegistry()