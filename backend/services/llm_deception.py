import httpx

from backend.config import settings


class DeceptionLLM:
    """Optional local Ollama adapter; failures fall back to the simulator."""

    async def generate(self, service_type: str, input_text: str) -> str | None:
        prompt = (
            "You are an isolated cyber-deception simulator. Respond as a fake "
            f"{service_type} service. Never provide real credentials, commands "
            "that affect the host, or instructions for harming systems. Keep the "
            f"response under 80 words. Request: {input_text}"
        )
        payload = {
            "model": settings.OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=0.5) as client:
                response = await client.post(
                    f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                    json=payload,
                )
                response.raise_for_status()
                text = response.json().get("response")
                return text.strip() if isinstance(text, str) and text.strip() else None
        except (httpx.HTTPError, ValueError):
            return None


deception_llm = DeceptionLLM()