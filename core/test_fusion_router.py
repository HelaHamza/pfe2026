# test_fusion_router.py
import pytest
from fusion_router import FusionRouter, DetectionSource

router = FusionRouter(ae_threshold=0.75)

def test_both():
    r = router.route({}, sigma_matches=["SSH Brute Force"], ae_score=0.92)
    assert r.source == DetectionSource.BOTH
    assert r.severity == "critical"

def test_sigma_only():
    r = router.route({}, sigma_matches=["SSH Brute Force"], ae_score=0.30)
    assert r.source == DetectionSource.SIGMA_ONLY

def test_ae_only():
    r = router.route({}, sigma_matches=[], ae_score=0.88)
    assert r.source == DetectionSource.AE_ONLY
    assert r.severity == "medium"

def test_none():
    r = router.route({}, sigma_matches=[], ae_score=0.20)
    assert r.source == DetectionSource.NONE

def test_ae_only_medium():
    r = router.route({}, sigma_matches=[], ae_score=0.80)
    assert r.severity == "medium"   # entre 0.75 et 0.90


    #test unitaire pour la fonction _sigma_severity sans grok client ni explication LLM