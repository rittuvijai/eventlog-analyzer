#!/usr/bin/env python3
"""
detector.py — Hybrid anomaly detection for Windows Event Logs.

Why hybrid?
-----------
Pure unsupervised ML (Isolation Forest) is excellent at finding *novel*
behavioral deviations — hosts acting unlike themselves or unlike their peers.
But it has a known blind spot: a point that is *extremely* anomalous in one
feature yet normal in ten others can score lower than a point that is merely
*odd* in several features at once. A 47-failed-logon brute force is the
canonical example.

Real UEBA/SIEM platforms solve this the same way: ML for the unknown unknowns,
deterministic rules for the known-bad patterns. This detector does both and
takes the maximum signal:

    Stage 1 — Signature rules (high precision):
        brute-force logon bursts, mass file-access (ransomware), audit-log
        clearing, impossible off-hours admin bursts, service-crash waves.
    Stage 2 — Isolation Forest (high recall on novel behavior):
        11-feature per-host hourly behavior vectors, unsupervised.

Output per event: anomaly_score 0..1, is_anomaly bool, detection_source
("signature" | "ml" | "both").

Usage:
    from detector import EventLogAnomalyDetector
    det = EventLogAnomalyDetector(contamination=0.02)
    scored = det.fit_predict("sample_logs/events.csv")
    ranking = det.host_risk_ranking(scored)
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLS = [
    "total_events", "failed_logons", "success_logons", "fail_ratio",
    "unique_event_codes", "unique_processes", "unique_users", "unique_src_ips",
    "offhours_ratio", "process_entropy", "error_events",
]

FAILED_LOGON = 4625
SUCCESS_LOGON = 4624
FILE_ACCESS = 5140
LOG_CLEARED = 1102
PRIV_LOGON = 4672  # special privileges assigned — admin logon marker
ERROR_CODES = {1000, 1001, 1002, 7031, 7034}

# Signature thresholds — tuned so normal baseline traffic never trips them,
# while the injected attack scenarios always do.
SIG_FAILED_LOGONS = 15      # brute-force burst within one host-hour
SIG_FAIL_RATIO = 0.8        # ...and dominated by failures
SIG_FILE_ACCESS = 100       # mass file touch = ransomware-like
SIG_ERROR_BURST = 8         # correlated service-crash wave per host-hour
SIG_PRIV_OFFHOURS = 1       # privileged logon outside business hours


def _shannon_entropy(counts: pd.Series) -> float:
    """Shannon entropy of a value-count distribution."""
    p = counts / counts.sum()
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


class EventLogAnomalyDetector:
    """
    Hybrid unsupervised + signature-based anomaly detector.

    Parameters
    ----------
    contamination : float
        Expected fraction of anomalous (host, hour) buckets for the ML stage.
    random_state : int
        Seed for reproducible results (important for demos).
    """

    def __init__(self, contamination: float = 0.02, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

    # ------------------------------------------------------------------
    # Feature engineering
    # ------------------------------------------------------------------
    @staticmethod
    def build_features(df: pd.DataFrame) -> pd.DataFrame:
        """Aggregate raw events into per-host, per-hour behavior vectors."""
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour_bucket"] = df["timestamp"].dt.floor("h")
        df["hour_of_day"] = df["timestamp"].dt.hour

        feats: list[dict] = []
        for (host, bucket), g in df.groupby(["host", "hour_bucket"]):
            fail = int((g["event_code"] == FAILED_LOGON).sum())
            succ = int((g["event_code"] == SUCCESS_LOGON).sum())
            offhours = int((~g["hour_of_day"].between(7, 19)).sum())
            # Privileged logons (4672) that happened off-hours — admin at 3 AM
            # is very different from admin at 3 PM.
            priv_offhours = int(
                ((g["event_code"] == PRIV_LOGON) & ~g["hour_of_day"].between(7, 19)).sum()
            )
            proc_vc = g.loc[g["process"].notna() & (g["process"] != ""), "process"].value_counts()
            ip_vc = g.loc[g["source_ip"].notna() & (g["source_ip"] != ""), "source_ip"]
            feats.append({
                "host": host,
                "hour_bucket": bucket,
                "total_events": len(g),
                "failed_logons": fail,
                "success_logons": succ,
                "fail_ratio": fail / (fail + succ + 1e-9),
                "unique_event_codes": g["event_code"].nunique(),
                "unique_processes": proc_vc.index.nunique(),
                "unique_users": g["user"].nunique(),
                "unique_src_ips": ip_vc.nunique(),
                "offhours_ratio": offhours / len(g),
                "process_entropy": _shannon_entropy(proc_vc) if len(proc_vc) else 0.0,
                "error_events": int(g["event_code"].isin(ERROR_CODES).sum()),
                "file_access": int((g["event_code"] == FILE_ACCESS).sum()),
                "log_cleared": int((g["event_code"] == LOG_CLEARED).sum()),
                "priv_offhours": priv_offhours,
            })
        return pd.DataFrame(feats)

    # ------------------------------------------------------------------
    # Stage 1 — signature rules
    # ------------------------------------------------------------------
    @staticmethod
    def signature_scores(feats: pd.DataFrame) -> pd.Series:
        """
        Deterministic high-precision rules. Returns 0..1 per bucket.
        Each rule targets a known-bad pattern; scores stack when several fire.
        """
        s = pd.Series(0.0, index=feats.index)

        # Brute force: burst of failed logons dominating the hour
        brute = (feats["failed_logons"] >= SIG_FAILED_LOGONS) & \
                (feats["fail_ratio"] >= SIG_FAIL_RATIO)
        s = s + brute.astype(float) * 0.95

        # Ransomware-like: mass file access in one hour
        ransom = feats["file_access"] >= SIG_FILE_ACCESS
        s = s + ransom.astype(float) * 0.95

        # Audit log cleared — almost never legitimate
        cleared = feats["log_cleared"] >= 1
        s = s + cleared.astype(float) * 0.90

        # Service-crash wave on a single host (fleet-wide correlation is
        # handled by the summarizer rolling these up)
        crash = feats["error_events"] >= SIG_ERROR_BURST
        s = s + crash.astype(float) * 0.70

        # Privileged logon off-hours — admin authenticating at 3 AM
        priv = feats["priv_offhours"] >= SIG_PRIV_OFFHOURS
        s = s + priv.astype(float) * 0.75

        return s.clip(0.0, 1.0)

    # ------------------------------------------------------------------
    # Stage 2 — ML (Isolation Forest)
    # ------------------------------------------------------------------
    def ml_scores(self, feats: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Fit Isolation Forest; return (score 0..1, is_anomaly bool)."""
        X = feats[FEATURE_COLS].fillna(0).to_numpy()
        Xs = self.scaler.fit_transform(X)
        raw = self.model.fit_predict(Xs)          # -1 = anomaly
        score = -self.model.decision_function(Xs)
        score = (score - score.min()) / (score.max() - score.min() + 1e-9)
        return score, raw == -1

    # ------------------------------------------------------------------
    # Combined fit / predict
    # ------------------------------------------------------------------
    def fit_predict(self, csv_path: str) -> pd.DataFrame:
        """
        Load events, run both stages, and return events with:

            anomaly_score     0..1 (max of signature and ML signals)
            is_anomaly        bool
            detection_source  "signature" | "ml" | "both"
        """
        df = pd.read_csv(csv_path, low_memory=False)
        feats = self.build_features(df)

        sig = self.signature_scores(feats)
        ml_score, ml_flag = self.ml_scores(feats)
        ml = pd.Series(ml_score, index=feats.index)

        feats["sig_score"] = sig
        feats["ml_score"] = ml
        feats["anomaly_score"] = np.maximum(sig, ml)
        feats["is_anomaly"] = (sig >= 0.5) | ml_flag
        feats["detection_source"] = np.select(
            [feats["is_anomaly"] & (sig >= 0.5) & ml_flag,
             feats["is_anomaly"] & (sig >= 0.5)],
            ["both", "signature"],
            default="ml",
        )

        key = feats.set_index(["host", "hour_bucket"])[
            ["anomaly_score", "is_anomaly", "detection_source"]]
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour_bucket"] = df["timestamp"].dt.floor("h")
        return df.join(key, on=["host", "hour_bucket"])

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------
    @staticmethod
    def host_risk_ranking(scored: pd.DataFrame) -> pd.DataFrame:
        """Rank hosts by risk: peak score, anomaly share, signature hits."""
        g = scored.groupby("host").agg(
            max_score=("anomaly_score", "max"),
            mean_score=("anomaly_score", "mean"),
            anomaly_events=("is_anomaly", "sum"),
            total_events=("is_anomaly", "size"),
            signature_hits=("detection_source", lambda s: (s != "ml").sum()),
        )
        g["anomaly_share"] = g["anomaly_events"] / g["total_events"]
        g["risk"] = (
            0.50 * g["max_score"]
            + 0.25 * g["anomaly_share"].clip(0, 1)
            + 0.15 * g["mean_score"]
            + 0.10 * (g["signature_hits"] > 0).astype(float)
        )
        return g.sort_values("risk", ascending=False).reset_index()

    @staticmethod
    def anomaly_timeline(scored: pd.DataFrame) -> pd.DataFrame:
        """Anomaly counts per hour — drives the dashboard timeline chart."""
        t = (
            scored[scored["is_anomaly"]]
            .groupby(scored["timestamp"].dt.floor("h"))
            .size()
            .rename("anomalies")
        )
        return t.reset_index().rename(columns={"timestamp": "hour"})
