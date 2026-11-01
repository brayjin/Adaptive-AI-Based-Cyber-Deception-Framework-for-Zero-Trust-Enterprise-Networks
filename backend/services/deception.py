import time
from datetime import datetime

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.deception import DeceptionAction
from backend.models.evaluations import ZeroTrustEvaluation
from backend.services.honeypots import honeypot_registry
from backend.services.llm_deception import deception_llm
from backend.services.rl_deception import DECEPTION_ACTIONS, adaptive_policy, compute_reward
from rl.train import get_trained_dqn


STRATEGIES = (
    "FAKE_SSH",
    "FAKE_WEB",
    "FAKE_DB",
    "FAKE_CREDENTIALS",
    "DIGITAL_TWIN",
    "NORMAL_RESPONSE",
)

STRATEGY_SERVICE_MAP = {
    "FAKE_SSH": "ssh",
    "FAKE_WEB": "web",
    "FAKE_DB": "db",
    "FAKE_CREDENTIALS": "credentials",
    "DIGITAL_TWIN": "digital_twin",
    "NORMAL_RESPONSE": None,
}


SERVICE_TYPES = {"ssh", "web", "db", "credentials", "digital_twin"}


class DeceptionService:
    """Select and record deception actions without connecting to live honeypots."""

    @staticmethod
    def choose_strategy(evaluation: ZeroTrustEvaluation) -> tuple[str, str, list, str, float]:
        if evaluation.trust_decision not in {"DECEIVE", "BLOCK"}:
            return "NORMAL_RESPONSE", "Risk decision does not require deception", [], "", 0.0

        stable_model = get_trained_dqn()
        if stable_model is not None:
            state = [
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
            ]
            action, _ = stable_model.predict(
                np.asarray(state, dtype=np.float32), deterministic=True
            )
            action_index = int(action)
            reward = compute_reward(state, action_index)
            return (
                DECEPTION_ACTIONS[action_index],
                "Stable-Baselines3 DQN selected strategy",
                [float(x) for x in state],
                str(action_index),
                float(reward),
            )

        if adaptive_policy.trained_episodes > 0:
            state = [
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
            ]
            selected_index = adaptive_policy.select_action(
                np.asarray(state, dtype=np.float32)
            )
            reward = compute_reward(state, selected_index)
            return (
                DECEPTION_ACTIONS[selected_index],
                "Native PyTorch DQN selected strategy",
                [float(x) for x in state],
                str(selected_index),
                float(reward),
            )

        if evaluation.device_score >= 0.70:
            return "FAKE_SSH", "Elevated risk against a privileged service", [], "", 0.0
        if evaluation.network_score >= 0.70:
            return "DIGITAL_TWIN", "Elevated network scanning or flood indicators", [], "", 0.0
        if evaluation.behaviour_score >= 0.70:
            return "FAKE_CREDENTIALS", "High-confidence malicious behaviour", [], "", 0.0
        return "FAKE_WEB", "Deception selected for elevated composite risk", [], "", 0.0

    async def decide(
        self,
        db: AsyncSession,
        evaluation: ZeroTrustEvaluation,
        strategy: str | None = None,
    ) -> DeceptionAction:
        # Prevent duplicate deception actions for the same evaluation.
        existing_result = await db.execute(
            select(DeceptionAction).where(
                DeceptionAction.evaluation_id == evaluation.id
            )
        )
        existing_action = existing_result.scalars().first()
        if existing_action is not None:
            return existing_action

        selected, reason, rl_state, rl_action, rl_reward = self.choose_strategy(evaluation)
        if strategy is not None:
            requested = strategy.upper()
            if requested not in STRATEGIES:
                raise ValueError(f"Unsupported deception strategy: {strategy}")
            if requested != "NORMAL_RESPONSE" and evaluation.trust_decision not in {"DECEIVE", "BLOCK"}:
                raise ValueError(
                    "Deception strategy override not permitted for "
                    f"{evaluation.trust_decision} risk decision"
                )
            selected = requested
            reason = "Strategy selected by caller"
            # Caller override means no RL policy action was used.
            rl_state = []
            rl_action = ""
            rl_reward = 0.0

        action = DeceptionAction(
            evaluation_id=evaluation.id,
            strategy_selected=selected,
            strategy_reason=f"{reason} [policy={evaluation.trust_decision}]",
            deception_target=f"honeypot_{selected.lower()}",
            rl_reward=rl_reward,
            rl_state=rl_state,
            rl_action=rl_action if rl_action != "" else "0",
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
        # Preserve policy enforcement: only evaluations that permitted deception
        # may be used to interact with a decoy.
        eval_result = await db.execute(
            select(ZeroTrustEvaluation).where(
                ZeroTrustEvaluation.id == action.evaluation_id
            )
        )
        evaluation = eval_result.scalar_one_or_none()
        if evaluation is None or evaluation.trust_decision not in {"DECEIVE", "BLOCK"}:
            raise ValueError("Decoy interaction is not permitted for this evaluation")

        expected_service = STRATEGY_SERVICE_MAP.get(action.strategy_selected)
        if expected_service is None:
            raise ValueError(
                f"Strategy {action.strategy_selected} does not support decoy interaction"
            )
        if service_type != expected_service:
            raise ValueError(
                f"Service type '{service_type}' does not match selected strategy "
                f"{action.strategy_selected}"
            )
        if service_type not in SERVICE_TYPES:
            raise ValueError(f"Unsupported deception service: {service_type}")

        start_time = time.perf_counter()
        started_at = datetime.utcnow()

        honeypot_response = honeypot_registry.handle(service_type, input_text)
        canary_triggered = honeypot_response.canary_triggered

        response_text = await deception_llm.generate(service_type, input_text)
        response_text = response_text or honeypot_response.response_text

        end_time = time.perf_counter()
        ended_at = datetime.utcnow()
        latency_ms = (end_time - start_time) * 1000.0

        entry = {
            "session_id": session_id,
            "service_type": service_type,
            "input": input_text,
            "response_text": response_text,
            "canary_triggered": canary_triggered,
            "canary_test_signal": canary_triggered,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "latency_ms": round(latency_ms, 3),
        }
        interaction_log = list(action.interaction_log or [])
        interaction_log.append(entry)
        action.interaction_log = interaction_log
        action.attacker_engagement_time = max(
            action.attacker_engagement_time,
            len(interaction_log),
        )
        action.ended_at = ended_at
        await db.flush()
        return {
            "session_id": session_id,
            "service_type": service_type,
            "response_text": response_text,
            "latency_ms": round(latency_ms, 3),
            "is_sandboxed": True,
            "canary_triggered": canary_triggered,
        }

    @staticmethod
    def _simulate_response(service_type: str, input_text: str) -> str:
        return honeypot_registry.handle(service_type, input_text).response_text


deception_service = DeceptionService()