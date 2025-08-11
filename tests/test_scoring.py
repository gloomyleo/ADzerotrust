from src.services.zero_trust_scoring import score_results
def test_scoring_basic():
    res = [{'pillar':'Identity'},{'pillar':'Identity','error':'x'},{'pillar':'Network'}]
    s = score_results(res)
    assert 'overall' in s and 0 <= s['overall'] <= 100
