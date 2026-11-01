import httpx

from backend.config import settings


SERVICE_HOSTS = {
    "ssh": "fake-ssh",
    "web": "fake-web",
    "db": "fake-db",
    "credentials": "fake-credentials",
    "digital_twin": "digital-twin",
}


class DockerHoneypotClient:
    async def handle(self, service_type: str, input_text: str) -> "HoneypotResponse":
        from backend.services.honeypots import HoneypotResponse

        host = SERVICE_HOSTS.get(service_type.lower())
        if host is None:
            raise ValueError(f"Unsupported deception service: {service_type}")
        url = f"https://{host}:8080/"
        timeout = settings.HONEYPOT_DOCKER_TIMEOUT
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            payload = response.json()
        text = payload.get("message") or payload.get("status") or "honeypot interaction recorded"
        return HoneypotResponse(
            service_type=service_type.lower(),
            response_text=str(text),
            canary_triggered="canary" in input_text.lower(),
        )