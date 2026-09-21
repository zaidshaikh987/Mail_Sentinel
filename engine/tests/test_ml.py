"""
The model layer.

The tests that matter here are not about accuracy — they are about the
properties that make the model defensible:

  * the label comes from the server configuration, never from the rule engine;
  * evaluation is grouped by configuration so it cannot leak;
  * the model never alters a finding or a grade;
  * missing features are encoded as MISSING rather than imputed.
"""

from __future__ import annotations

import os

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("sklearn")

from mailsentinel.features import CORE_FEATURE_COUNT, FEATURE_NAMES, MISSING, extract
from mailsentinel.ml.dataset import ServerProfile, generate, posture_of, sample_profile
from mailsentinel.models import CertVisibility


# --------------------------------------------------------------------------
# labelling
# --------------------------------------------------------------------------

def test_label_ladder_is_ordered():
    """Each rung of the posture ladder must be reachable and correctly ranked."""
    base = dict(
        name="x", tls_version=13, cipher_bits=256, cipher_mode=4, cipher_recommended=1,
        kex_family=5, kex_bits=3072, forward_secrecy=1, cert_key_bits=2048,
        cert_key_algo=2, cert_sig_hash=3, cert_days_to_expiry=300,
        cert_self_signed=0, chain_valid=1, name_match=1,
        starttls_offered=1, starttls_completed=1, cleartext_auth=0,
    )
    assert posture_of(ServerProfile(**base)) == "secure"
    assert posture_of(ServerProfile(**{**base, "cert_self_signed": 1})) == "weak"
    assert posture_of(ServerProfile(**{**base, "cipher_mode": 2})) == "weak"
    assert posture_of(ServerProfile(**{**base, "tls_version": 10})) == "vulnerable"
    assert posture_of(ServerProfile(**{**base, "forward_secrecy": 0})) == "vulnerable"
    assert posture_of(ServerProfile(**{**base, "cert_key_bits": 1536})) == "vulnerable"
    assert posture_of(ServerProfile(**{**base, "cert_days_to_expiry": -1})) == "critical"
    assert posture_of(ServerProfile(**{**base, "cipher_mode": 1})) == "critical"
    assert posture_of(ServerProfile(**{**base, "tls_version": 0})) == "critical"


def test_labels_never_come_from_the_rule_engine():
    """
    Guard against the circularity that would make the model worthless: the
    dataset module must not import or call the rule engine.
    """
    import inspect

    from mailsentinel.ml import dataset

    src = inspect.getsource(dataset)
    assert "scoring" not in src
    assert "apply_rules" not in src


def test_dataset_covers_all_classes_and_many_groups():
    ds = generate(n_profiles=200, sessions_per_profile=4, seed=7)
    assert len(set(ds.y)) == 4, "all four posture classes must appear"
    assert len(set(ds.groups)) >= 150, "grouped CV needs many distinct configurations"
    assert len(ds.X) == len(ds.y) == len(ds.groups) == len(ds.cert_masked)
    assert all(len(row) == len(FEATURE_NAMES) for row in ds.X)


def test_tls13_masking_hides_exactly_the_certificate_features():
    ds = generate(n_profiles=60, sessions_per_profile=6, tls13_mask_rate=1.0, seed=3)
    cert_idx = [FEATURE_NAMES.index(n) for n in (
        "cert_key_bits", "cert_key_algo", "cert_sig_hash", "cert_days_to_expiry",
        "cert_self_signed", "chain_valid", "name_match",
    )]
    version_idx = FEATURE_NAMES.index("tls_version")
    masked_rows = [row for row, m in zip(ds.X, ds.cert_masked) if m]
    assert masked_rows, "masking should produce rows"
    for row in masked_rows:
        for i in cert_idx:
            assert row[i] == MISSING
        assert row[version_idx] > 0, "handshake metadata still visible"


def test_no_masking_when_disabled():
    ds = generate(n_profiles=40, sessions_per_profile=4, tls13_mask_rate=0.0, seed=5)
    assert not any(ds.cert_masked)


# --------------------------------------------------------------------------
# features
# --------------------------------------------------------------------------

def test_feature_vector_shape_and_core_count():
    assert len(FEATURE_NAMES) == 26
    assert CORE_FEATURE_COUNT == 18
    assert FEATURE_NAMES[:CORE_FEATURE_COUNT][-1] == "cleartext_auth"


def test_missing_certificate_features_are_encoded_not_imputed(analysed):
    """
    Cleartext sessions have no certificate.  Those features must read MISSING,
    because *whether* a field was observable is itself a signal.
    """
    session = analysed["imap_cleartext"].sessions[0]
    assert session.cert_visibility == CertVisibility.ABSENT
    f = extract(session)
    assert f["cert_visible"] == 0.0
    for name in ("cert_key_bits", "cert_sig_hash", "chain_valid", "name_match"):
        assert f[name] == MISSING


def test_features_are_extracted_for_every_demo_session(analysed):
    for report in analysed.values():
        for s in report.sessions:
            f = extract(s)
            assert set(f) == set(FEATURE_NAMES)
            assert all(isinstance(v, float) for v in f.values())


# --------------------------------------------------------------------------
# evaluation discipline
# --------------------------------------------------------------------------

@pytest.mark.slow
def test_grouped_cv_does_not_leak():
    """
    A grouped split must score meaningfully below a (leaky) random split.  If
    the two agree, the grouping is not doing its job.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import GroupKFold, KFold, cross_val_score

    ds = generate(n_profiles=120, sessions_per_profile=6, seed=11)
    X = np.asarray(ds.X)
    y = np.asarray(ds.y)
    g = np.asarray(ds.groups)

    clf = RandomForestClassifier(n_estimators=80, random_state=0, n_jobs=-1)
    grouped = cross_val_score(clf, X, y, groups=g, cv=GroupKFold(4)).mean()
    random_split = cross_val_score(clf, X, y, cv=KFold(4, shuffle=True, random_state=0)).mean()

    assert grouped < random_split, "grouping must be stricter than a random split"
    assert grouped > 0.6, "but the model should still generalise"


def test_model_never_modifies_findings_or_grade(analysed, tmp_path):
    """
    The model is advisory.  Running it must leave every deterministic verdict
    byte-identical.
    """
    from mailsentinel.ml.predict import ModelUnavailable, annotate

    report = analysed["pop3_starttls"]
    sessions = report.sessions
    before = [
        ([f.rule_id for f in s.findings], s.grade.letter, s.grade.raw_score)
        for s in sessions
    ]
    try:
        annotate(sessions)
    except ModelUnavailable as exc:
        # Reports the real reason: a missing artifact and a version-mismatched
        # one are both "unavailable", and a bare message would send whoever
        # reads this skip looking for the wrong problem.
        pytest.skip(f"no usable model: {exc}")

    after = [
        ([f.rule_id for f in s.findings], s.grade.letter, s.grade.raw_score)
        for s in sessions
    ]
    assert before == after
    assert all(s.ml is not None for s in sessions)


def test_predictions_carry_an_explanation(analysed):
    from mailsentinel.ml.predict import ModelUnavailable, annotate

    sessions = analysed["smtp_starttls"].sessions
    try:
        annotate(sessions)
    except ModelUnavailable as exc:
        # Reports the real reason: a missing artifact and a version-mismatched
        # one are both "unavailable", and a bare message would send whoever
        # reads this skip looking for the wrong problem.
        pytest.skip(f"no usable model: {exc}")

    for s in sessions:
        assert s.ml.risk_class in ("secure", "weak", "vulnerable", "critical")
        assert type(s.ml.risk_class) is str, "must be a plain str, not np.str_"
        assert 0.0 <= s.ml.risk_score <= 1.0
        assert abs(sum(s.ml.class_probabilities.values()) - 1.0) < 1e-9
        assert s.ml.explanation
        # risk_score answers "how bad could this be" (P(critical)); the
        # confidence quoted in the sentence answers "how sure is the model of
        # the class it named". Quoting the first as the second understated a
        # 0.73 call as 0.04.
        confidence = s.ml.class_probabilities[s.ml.risk_class]
        assert f"confidence {confidence:.2f}" in s.ml.explanation, s.ml.explanation
        assert s.ml.risk_score == s.ml.class_probabilities.get("critical", s.ml.risk_score)


def test_rounded_probabilities_still_sum_to_one():
    """
    Rounding each class independently lets a four-class vector drift by up to
    2e-4, so a report could print four numbers that visibly fail to add up.
    The apportionment must make the total exact without moving any value by
    more than one unit in the last place.
    """
    from mailsentinel.ml.predict import _round_to_one

    cases = [
        [0.10804, 0.03012, 0.57866, 0.28312],   # the vector that caught this
        [0.25, 0.25, 0.25, 0.25],
        [1.0, 0.0, 0.0, 0.0],
        [1 / 3, 1 / 3, 1 / 3],
        [0.99995, 0.00005],
    ]
    for raw in cases:
        out = _round_to_one(raw)
        assert abs(sum(out) - 1.0) < 1e-9, (raw, out, sum(out))
        for got, want in zip(out, raw):
            assert abs(got - want) <= 1e-4 + 1e-12, (raw, out)
        assert all(v >= 0.0 for v in out), out


def test_anomaly_flag_suppressed_when_population_too_small(analysed):
    """
    One session is not a population.  Calling it an outlier would be
    meaningless, so the flag must stay false however odd the session looks.
    """
    from mailsentinel.ml.predict import ModelUnavailable, annotate

    sessions = analysed["imap_cleartext"].sessions
    assert len(sessions) < 8
    try:
        annotate(sessions)
    except ModelUnavailable as exc:
        # Reports the real reason: a missing artifact and a version-mismatched
        # one are both "unavailable", and a bare message would send whoever
        # reads this skip looking for the wrong problem.
        pytest.skip(f"no usable model: {exc}")
    assert all(s.ml.anomaly is False for s in sessions)


# --------------------------------------------------------------------------
# model portability
# --------------------------------------------------------------------------

def _doctored_artifact(tmp_path):
    """
    A copy of the shipped model whose recorded scikit-learn version is wrong.

    Building it means unpickling the real artifact, which on a machine whose
    scikit-learn differs emits the very InconsistentVersionWarning this feature
    exists to prevent. That warning is about the fixture, not the code under
    test, so it is silenced here — the assertions, not the log, decide.
    """
    import warnings

    import joblib

    from mailsentinel.ml.train import DEFAULT_ARTIFACT_DIR

    src = os.path.join(DEFAULT_ARTIFACT_DIR, "posture_model.joblib")
    if not os.path.exists(src):
        pytest.skip("no model artifact present")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        bundle = joblib.load(src)
    bundle["sklearn_version"] = "0.0.0-not-a-real-version"
    fake = tmp_path / "mismatched.joblib"
    joblib.dump(bundle, fake)
    return str(fake)


def test_model_records_the_sklearn_it_was_trained_with():
    """
    Without this, a pickle from a different scikit-learn loads with a warning
    saying results "may be invalid" — and a forensic tool must not publish a
    number its own library calls unreliable.
    """
    from mailsentinel.ml.predict import load_model, ModelUnavailable

    try:
        bundle = load_model()
    except Exception as exc:
        pytest.skip(f"no usable model artifact: {exc}")
    assert bundle.get("sklearn_version"), "the artifact must record its build version"


def test_version_mismatch_is_refused_not_silently_used(tmp_path):
    from mailsentinel.ml.predict import (
        ModelUnavailable,
        ModelVersionMismatch,
        load_model,
    )

    fake = _doctored_artifact(tmp_path)

    with pytest.raises(ModelVersionMismatch) as caught:
        load_model(fake)
    # The message has to tell the operator what to do about it.
    assert "mailsentinel.ml.train" in str(caught.value)
    # Callers only ever ask "can I use the model here?", so the specific
    # mismatch error must satisfy the general one.
    assert isinstance(caught.value, ModelUnavailable)


def test_analysis_survives_an_unusable_model(captures, tmp_path):
    """
    The model is advisory. A broken artifact must degrade to a warning, never
    take down an analysis — every finding and grade comes from the rule engine.
    """
    from mailsentinel.pipeline import analyse_capture

    fake = _doctored_artifact(tmp_path)

    report = analyse_capture(captures["pop3_starttls"], run_ml=True, model_path=fake)

    assert report.sessions, "the analysis must still produce sessions"
    assert report.sessions[0].grade is not None
    assert report.sessions[0].findings
    skipped = [w for w in report.warnings if "Model stage skipped" in w]
    assert skipped, report.warnings
    # The warning has to be actionable on its own — this string is all the
    # operator sees in a report or a CI log.
    assert "mailsentinel.ml.train" in skipped[0], skipped[0]
