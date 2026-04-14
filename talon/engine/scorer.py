def score_result(
    match_points: int,
    has_kev: bool,
    has_poc: bool,
    has_edb: bool,
) -> int:
    """
    Scoring breakdown:
      match_points : 20 (Exact), 5 (Partial), -10 (Description only)
      KEV          : +50  actively exploited in the wild per CISA
      PoC          : +30  public proof-of-concept exists (nomi-sec)
      ExploitDB    : +20  weaponized exploit in ExploitDB
    """
    score = match_points
    if has_kev:
        score += 50
    if has_poc:
        score += 30
    if has_edb:
        score += 20
    return score


def label_for_score(score: int) -> str:
    if score >= 100:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW CONFIDENCE"
