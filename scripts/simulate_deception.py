import argparse
import asyncio

import httpx


async def simulate(base_url: str) -> dict:
    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        generated = await client.post(
            "/api/v1/events/generate",
            json={"scenario": "bruteforce", "count": 1},
        )
        generated.raise_for_status()
        event_id = generated.json()["event_ids"][0]

        evaluation = await client.post(
            "/api/v1/zerotrust/evaluate",
            json={"event_id": event_id},
        )
        evaluation.raise_for_status()
        evaluation_data = evaluation.json()

        decision = await client.post(
            "/api/v1/deception/decide",
            json={"evaluation_id": evaluation_data["id"]},
        )
        decision.raise_for_status()
        action = decision.json()

        interaction = await client.post(
            "/api/v1/deception/interact",
            json={
                "action_id": action["id"],
                "session_id": "simulation-session",
                "service_type": "ssh",
                "input_text": "CANARY_TOKEN cat /etc/passwd",
            },
        )
        interaction.raise_for_status()
        return {
            "event_id": event_id,
            "evaluation": evaluation_data,
            "action": action,
            "interaction": interaction.json(),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a cyber-deception API simulation")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    result = asyncio.run(simulate(args.base_url.rstrip("/")))
    print(result)


if __name__ == "__main__":
    main()