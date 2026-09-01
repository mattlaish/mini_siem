import investigation_profiles as profiles


def _alert(rule_name, description=""):
    return {"rule_name": rule_name, "description": description}


def test_profile_classification_explicit_types():
    assert profiles.classify_investigation(
        _alert("nxlog_severity_event"), [{"msg_id": "4625", "message": "failed logon"}]
    ).key == "auth_anomaly"

    assert profiles.classify_investigation(
        _alert("nxlog_severity_event"), [{"msg_id": "4720", "message": "account created"}]
    ).key == "account_privilege"

    assert profiles.classify_investigation(
        _alert("threat_intel_match", "IOC match (ip): 203.0.113.9"), []
    ).key == "ioc_hit"

    assert profiles.classify_investigation(
        _alert("high_severity_event"),
        [{"msg_id": "", "app_name": "Sophos", "source_ip": "sophos", "message": "malware detected and quarantined"}],
    ).key == "malware_sophos"

    assert profiles.classify_investigation(
        _alert("firewall_c2_beacon", "Repeated beaconing to command and control"), []
    ).key == "firewall_c2"


def test_unrelated_nxlog_warning_does_not_become_auth_profile_just_from_rule_name():
    assert profiles.classify_investigation(
        _alert("nxlog_severity_event", "NXLog Windows warning severity event: service installed"),
        [{"msg_id": "7045", "message": "A service was installed"}],
    ).key == "generic"


def test_windows_explicit_credentials_logon_uses_auth_profile():
    assert profiles.classify_investigation(
        _alert("nxlog_severity_event"), [{"msg_id": "4648", "message": "explicit credentials"}]
    ).key == "auth_anomaly"
