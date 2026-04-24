def detect_identity_type(source: str, os: str, asset_type: str, tags: str,
                         hostname: str = "", fqdn: str = "") -> str:
    s = source.lower(); o = os.lower(); at = asset_type.lower()
    t = tags.lower(); h = hostname.lower()
    if at in ("web", "website", "domain", "webapp") or \
       any(x in t for x in ("website", "webapp", "domain")) or \
       h.startswith("www."):
        return "web"
    if any(x in s for x in ("aws", "azure", "gcp", "cloud")) or at == "cloud":
        return "cloud_resource"
    if at == "container" or "container" in t or "docker" in o:
        return "container"
    if at == "image" or "image" in t:
        return "image"
    if at == "repo" or "git" in t or "repo" in t:
        return "repo"
    if at == "app" or "application" in at:
        return "app"
    # OS-based workstation vs server detection
    if at in ("workstation", "laptop") or \
       any(x in o for x in ("windows 10", "windows 11", "macos", "mac os x", "mac os")):
        return "workstation"
    if at == "server" or \
       any(x in o for x in ("windows server", "ubuntu", "centos", "rhel", "debian",
                             "fedora", "suse", "amazon linux", "oracle linux", "rocky",
                             "alma", "kali", "parrot")):
        return "server"
    return "host"
