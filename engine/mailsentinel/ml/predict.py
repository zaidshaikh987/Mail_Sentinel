"""
Prediction and explanation.

Three jobs, each with a defensible reason to exist — and none of them decides
whether a cipher is weak.  That is a fact, and facts belong to the rule engine.

1. **Posture estimation** where the rules must abstain.  On a TLS 1.3 session
   the certificate is encrypted and seven of the eighteen core features are
   unavailable; the rule engine cannot judge certificate posture at all, while
   a model trained across configurations still can estimate it.
2. **Anomaly detection**, fit per capture on that capture's own sessions.  It
   answers a question the rules cannot phrase: "23 sessions to this server
   negotiated TLS 1.3 and one negotiated TLS 1.0 — why?"
3. **Attribution** via TreeSHAP, so every prediction carries the reason for it.
   A forensic verdict that cannot be explained is worthless in an investigation.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Optional

import numpy as np

from ..features import FEATURE_NAMES, to_row
from ..models import MLVerdict, Session, ShapContribution
from .train import DEFAULT_ARTIFACT_DIR, MODEL_VERSION

# Below this many sessions an IsolationForest has no population to compare
# against and "outlier" is meaningless.
MIN_SESSIONS_FOR_ANOMALY = 8

# Human-readable summaries for the features that most often drive a verdict.
_FEATURE_PHRASES = {
    "tls_version": "negotiated TLS version",
    "cipher_key_bits": "symmetric key size",
    "cipher_mode": "cipher mode (AEAD vs CBC)",
    "cipher_iana_recommended": "IANA recommendation status of the suite",
    "kex_family": "key-exchange family",
    "kex_bits_equiv": "key-exchange strength",
    "forward_secrecy": "forward secrecy",
    "cert_visible": "certificate visibility",
    "cert_key_bits": "certificate key size",
    "cert_sig_hash": "certificate signature hash",
    "cert_days_to_expiry": "days to certificate expiry",
    "cert_self_signed": "self-signed certificate",
    "chain_valid": "chain validity",
    "name_match": "certificate name match",
    "starttls_offered": "STARTTLS advertisement",
    "starttls_completed": "STARTTLS upgrade completion",
    "cleartext_auth": "cleartext credentials",
}


class ModelUnavailable(RuntimeError):
    """No usable model in this environment. Callers should degrade, not fail."""


class ModelVersionMismatch(ModelUnavailable):
    """
    The stored model was pickled by a different scikit-learn.

    A subclass of ``ModelUnavailable`` on purpose: to every caller the practical
    question is "can I use the model here?", and the answer is no. Only code
    that wants to *explain* the reason needs to distinguish the two.
    """


@lru_cache(maxsize=4)
def load_model(model_path: Optional[str] = None) -> dict[str, Any]:
    """
    Load the model bundle, refusing one that was pickled by a different
    scikit-learn.

    scikit-learn pickles are not portable across versions. Loading a mismatched
    one emits a wall of ``InconsistentVersionWarning`` saying results "may be
    invalid" — and a forensic tool must not quietly produce output that its own
    library calls unreliable. Better to skip the model stage with an actionable
    message than to publish a number nobody should trust.
    """
    import warnings

    import joblib
    import sklearn

    path = model_path or os.path.join(DEFAULT_ARTIFACT_DIR, "posture_model.joblib")
    if not os.path.exists(path):
        raise ModelUnavailable(
            f"no trained model at {path} — run `python -m mailsentinel.ml.train`"
        )

    with warnings.catch_warnings():
        # The bundle's own metadata is the check; sklearn's per-estimator
        # warnings would just be noise repeated once per tree ensemble.
        warnings.simplefilter("ignore")
        try:
            bundle = joblib.load(path)
        except Exception as exc:
            raise ModelUnavailable(
                f"the stored model could not be loaded ({exc.__class__.__name__}: {exc}). "
                f"Retrain it for this environment: python -m mailsentinel.ml.train"
            ) from exc

    trained_with = bundle.get("sklearn_version")
    if trained_with and trained_with != sklearn.__version__:
        raise ModelVersionMismatch(
            f"the stored model was trained with scikit-learn {trained_with} but this "
            f"environment has {sklearn.__version__}, and scikit-learn pickles are not "
            f"portable across versions. Retrain it — it takes about half a minute and "
            f"is deterministic: python -m mailsentinel.ml.train"
        )
    return bundle


def _round_to_one(values, places: int = 4) -> list[float]:
    """
    Round a probability vector to ``places`` decimals so that it still sums to
    exactly 1.

    Rounding each class independently does not preserve the sum: four classes
    rounded to 4dp can drift by up to 2e-4, so a report can print 0.108, 0.030,
    0.579 and 0.283 and invite the reader to notice they make 0.9999. The
    largest-remainder method assigns the leftover units to the classes with the
    biggest truncated fractions, which keeps every value within one unit of its
    true rounding and makes the total exact by construction.
    """
    import math

    scale = 10**places
    scaled = [float(v) * scale for v in values]
    floors = [math.floor(s) for s in scaled]
    # The target is one whole unit, not the input's own sum. ``predict_proba``
    # is normalised but only to float precision, and anchoring to the input
    # would carry that drift straight into the printed total.
    remainder = scale - sum(floors)
    # Largest fractional part first when handing out units, smallest first when
    # taking them back.
    order = sorted(range(len(scaled)), key=lambda i: scaled[i] - floors[i], reverse=remainder > 0)
    for i in order[: abs(remainder)]:
        floors[i] += 1 if remainder > 0 else -1
    return [f / scale for f in floors]


def _explain(bundle: dict, row: np.ndarray, predicted_index: int) -> list[ShapContribution]:
    """
    TreeSHAP attribution for one prediction.

    Background subsampling is not needed for TreeExplainer on a forest this
    size; the exact tree-path algorithm runs in milliseconds per sample.
    """
    try:
        import shap
    except ImportError:
        return []
    try:
        explainer = _tree_explainer(id(bundle["classifier"]), bundle["classifier"])
        values = explainer.shap_values(row.reshape(1, -1), check_additivity=False)
        # shap returns either a list per class or a 3-D array depending on version
        if isinstance(values, list):
            arr = np.asarray(values[predicted_index]).ravel()
        else:
            arr = np.asarray(values)
            arr = arr[0, :, predicted_index] if arr.ndim == 3 else arr.ravel()
        pairs = [
            ShapContribution(
                feature=name,
                value=float(row[i]),
                contribution=round(float(arr[i]), 5),
            )
            for i, name in enumerate(FEATURE_NAMES)
            if i < len(arr)
        ]
        pairs.sort(key=lambda c: -abs(c.contribution))
        return pairs[:10]
    except Exception:
        return []


@lru_cache(maxsize=4)
def _tree_explainer(_key: int, clf):  # cached: building the explainer dominates cost
    import shap

    return shap.TreeExplainer(clf)


def _narrate(verdict: MLVerdict, session: Session) -> str:
    # The confidence quoted for a class must be *that class's* probability.
    # `risk_score` is P(critical) — a deliberately different question — and
    # printing it here read as "posture 'weak' (confidence 0.04)" on a session
    # the model actually called weak with probability 0.73.
    confidence = verdict.class_probabilities.get(verdict.risk_class, verdict.risk_score or 0.0)
    top = [c for c in verdict.shap if c.contribution > 0][:3]
    if not top:
        return f"Model estimates posture '{verdict.risk_class}' (confidence {confidence:.2f})."
    drivers = ", ".join(_FEATURE_PHRASES.get(c.feature, c.feature) for c in top)
    base = (
        f"Model estimates posture '{verdict.risk_class}' "
        f"(confidence {confidence:.2f}); the largest contributions come "
        f"from {drivers}."
    )
    if session.cert_visibility.value == "encrypted_tls13":
        base += (
            " Certificate features were unavailable on this TLS 1.3 session, so "
            "this estimate rests on handshake metadata alone — which is exactly "
            "the case the model exists to cover."
        )
    return base


def annotate(
    sessions: list[Session],
    model_path: Optional[str] = None,
) -> None:
    """Fill in ``session.ml`` for every session.  Never touches findings or grade."""
    if not sessions:
        return
    bundle = load_model(model_path)
    clf = bundle["classifier"]
    # `clf.classes_` is a numpy array, so its elements are ``np.str_``. That is a
    # str subclass and mostly behaves, but it reprs as ``np.str_('critical')`` —
    # which is what a JSON report or a log line would show a reader.
    classes = [str(c) for c in bundle["classes"]]

    X = np.asarray([to_row(s.features or {}) for s in sessions], dtype=float)
    probs = clf.predict_proba(X)

    # Anomaly detection is refit on this capture's own population, so "unusual"
    # means unusual *here* rather than unusual relative to training data.
    anomaly_flags = [False] * len(sessions)
    anomaly_scores: list[Optional[float]] = [None] * len(sessions)
    if len(sessions) >= MIN_SESSIONS_FOR_ANOMALY:
        from sklearn.ensemble import IsolationForest

        local = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=26159,
        )
        local.fit(X)
        raw = local.decision_function(X)
        pred = local.predict(X)
        for i in range(len(sessions)):
            anomaly_flags[i] = bool(pred[i] == -1)
            anomaly_scores[i] = round(float(raw[i]), 5)
    else:
        # Fall back to the trained global model purely as a score, with the
        # flag suppressed: too few sessions to call anything an outlier.
        iso = bundle.get("isolation")
        if iso is not None:
            raw = iso.decision_function(X)
            for i in range(len(sessions)):
                anomaly_scores[i] = round(float(raw[i]), 5)

    worst = classes.index("critical") if "critical" in classes else 0
    for i, s in enumerate(sessions):
        p = probs[i]
        idx = int(np.argmax(p))
        # Round once, here, so the risk score and the per-class table are the
        # same numbers — a report that showed 0.11 in one place and 0.1080 in
        # another would be answering the same question twice.
        shown = _round_to_one(p)
        verdict = MLVerdict(
            risk_class=classes[idx],
            risk_score=shown[worst],
            class_probabilities={str(c): shown[j] for j, c in enumerate(classes)},
            anomaly=anomaly_flags[i],
            anomaly_score=anomaly_scores[i],
            shap=_explain(bundle, X[i], idx),
            model_version=bundle.get("model_version", MODEL_VERSION),
        )
        verdict.explanation = _narrate(verdict, s)
        s.ml = verdict
