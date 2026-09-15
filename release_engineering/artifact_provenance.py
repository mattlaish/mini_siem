# Artifact provenance baseline

def create_record(source, artifact, checksum):
    return {
        "source": source,
        "artifact": artifact,
        "checksum": checksum,
    }
