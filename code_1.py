# prompt_shield/middleware.py

class PromptShield:
    def __init__(self, threshold=0.65):
        self.threshold = threshold
        self.session_scores = {}

    def inspect(self, prompt: str, session_id: str = "default") -> dict:
        l1 = self._layer1_pattern_score(prompt)
        l2 = self._layer2_semantic_score(prompt)
        risk = self._layer3_risk_score(l1, l2, session_id)

        if risk >= self.threshold:
            verdict = "BLOCK"
        elif risk >= 0.35:
            verdict = "FLAG"
        else:
            verdict = "PASS"

        return {
            "verdict": verdict,
            "risk_score": round(risk, 3),
            "layer1_score": round(l1, 3),
            "layer2_score": round(l2, 3),
            "session_id": session_id,
        }