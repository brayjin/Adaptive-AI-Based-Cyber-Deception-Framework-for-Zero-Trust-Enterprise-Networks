from datetime import datetime

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.deception import DeceptionAction
from backend.models.evaluations import ZeroTrustEvaluation
from backend.services.honeypots import honeypot_registry
from backend.services.llm_deception import deception_llm
from backend.services.rl_deception import DECEPTION_ACTIONS, adaptive_policy
from rl.train import get_trained_dqn


STRATEGIES = (
    "FAKE_SSH",
    "FAKE_WEB",
    "FAKE_DB",
    "FAKE_CREDENTIALS",
    "DIGITAL_TWIN",
    "NORMAL_RESPONSE",
)

SERVICE_TYPES = {"ssh", "web", "db", "credentials", "digital_twin"}


class DeceptionService:
    """Select and record deception actions without connecting to live honeypots."""

    @staticmethod
    def choose_strategy(evaluation: ZeroTrustEvaluation) -> tuple[str, str]:
        if evaluation.trust_decision not in {"DECEIVE", "BLOCK"}:
            return "NORMAL_RESPONSE", "Risk decision does not require deception"

        stable_model = get_trained_dqn()
        if stable_model is not None:
            state = np.asarray(
                [
                    evaluation.identity_score,
                    evaluation.behaviour_score,
                    evaluation.network_score,
                    0.5,
                    evaluation.device_score,
                    evaluation.context_score,
                    evaluation.composite_risk_score,
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                ],
                dtype=np.float32,
            )
            action, _ = stable_model.predict(state, deterministic=True)
            return DECEPTION_ACTIONS[int(action)], "Stable-Baselines3 DQN selected strategy"

        if adaptive_policy.trained_episodes > 0:
            state = np.asarray(
                [
                    evaluation.identity_score,
                    evaluation.behaviour_score,
                    evaluation.network_score,
                    0.5,
                    evaluation.device_score,
                    evaluation.context_score,
                    evaluation.composite_risk_score,
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                    0.0,
                ],
                dtype=np.float32,
            )
            selected = DECEPTION_ACTIONS[adaptive_policy.select_action(state)]
            return selected, "Native PyTorch DQN selected strategy"

        if evaluation.device_score >= 0.70:
            return "FAKE_SSH", "Elevated risk against a privileged service"
        if evaluation.network_score >= 0.70:
            return "DIGITAL_TWIN", "Elevated network scanning or flood indicators"
        if evaluation.behaviour_score >= 0.70:
            return "FAKE_CREDENTIALS", "High-confidence malicious behaviour"
        return "FAKE_WEB", "Deception selected for elevated composite risk"

    async def decide(
        self,
        db: AsyncSession,
        evaluation: ZeroTrustEvaluation,
        strategy: str | None = None,
    ) -> DeceptionAction:
        selected, reason = self.choose_strategy(evaluation)
        if strategy is not None:
            selected = strategy.upper()
            if selected not in STRATEGIES:
                raise ValueError(f"Unsupported deception strategy: {strategy}")
            reason = "Strategy selected by caller"

        action = DeceptionAction(
            evaluation_id=evaluation.id,
            strategy_selected=selected,
            strategy_reason=reason,
            deception_target=f"honeypot_{selected.lower()}",
            rl_action="0",
            rl_state=[],
        )
        db.add(action)
        await db.flush()
        return action

    async def list_actions(
        self,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
    ) -> list[DeceptionAction]:
        result = await db.execute(
            select(DeceptionAction)
            .order_by(DeceptionAction.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def record_interaction(
        self,
        db: AsyncSession,
        action: DeceptionAction,
        session_id: str,
        service_type: str,
        input_text: str,
    ) -> dict:
        service_type = service_type.lower()
        if service_type not in SERVICE_TYPES:
            raise ValueError(f"Unsupported deception service: {service_type}")

        honeypot_response = honeypot_registry.handle(service_type, input_text)
        canary_triggered = honeypot_response.canary_triggered
        entry = {
            "session_id": session_id,
            "service_type": service_type,
            "input": input_text,
            "canary_triggered": canary_triggered,
            "received_at": datetime.utcnow().isoformat(),
        }
        interaction_log = list(action.interaction_log or [])
        interaction_log.append(entry)
        action.interaction_log = interaction_log
        action.attacker_engagement_time = max(
            action.attacker_engagement_time,
            len(interaction_log),
        )
        action.deception_success = action.deception_success or canary_triggered
        await db.flush()
        response_text = await deception_llm.generate(service_type, input_text)
        response_text = response_text or self._simulate_response(service_type, input_text)
        return {
            "session_id": session_id,
            "service_type": service_type,
            "response_text": response_text,
            "latency_ms": 0.0,
            "is_sandboxed": True,
        }

    @staticmethod
    def _simulate_response(service_type: str, input_text: str) -> str:
        return honeypot_registry.handle(service_type, input_text).response_text


deception_service = DeceptionService()