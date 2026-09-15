from backup_restore import validate_backup

def test_backup_restore_checksum_contract(tmp_path):
    p=tmp_path/"backup.dump"
    p.write_bytes(b"backup")
    import hashlib
    assert validate_backup(str(p), hashlib.sha256(b"backup").hexdigest())
