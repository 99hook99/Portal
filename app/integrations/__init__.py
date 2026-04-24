from app.config import settings


def get_integration(scanner_type: str, db=None):
    if scanner_type == "nessus":
        from app.integrations.nessus import NessusIntegration
        if db:
            try:
                from app.models import NessusConfig
                cfg = db.query(NessusConfig).first()
                if cfg and cfg.url and cfg.access_key:
                    return NessusIntegration(
                        url=cfg.url,
                        access_key=cfg.access_key,
                        secret_key=cfg.secret_key,
                        verify_ssl=False,
                        excluded_folders=cfg.excluded_folders,
                    )
            except Exception:
                pass
        if settings.NESSUS_URL and settings.NESSUS_ACCESS_KEY:
            return NessusIntegration(
                url=settings.NESSUS_URL,
                access_key=settings.NESSUS_ACCESS_KEY,
                secret_key=settings.NESSUS_SECRET_KEY,
                verify_ssl=settings.NESSUS_VERIFY_SSL,
            )
        return None

    if scanner_type == "mde":
        from app.integrations.mde import MDEIntegration
        return MDEIntegration(
            tenant_id=settings.MDE_TENANT_ID,
            client_id=settings.MDE_CLIENT_ID,
            client_secret=settings.MDE_CLIENT_SECRET,
        )

    if scanner_type == "openvas":
        from app.integrations.openvas import OpenVASIntegration
        return OpenVASIntegration(
            host=settings.OPENVAS_HOST,
            port=settings.OPENVAS_PORT,
            username=settings.OPENVAS_USERNAME,
            password=settings.OPENVAS_PASSWORD,
        )

    if scanner_type == "nmap":
        from app.integrations.nmap import NmapIntegration
        return NmapIntegration(
            targets=settings.NMAP_TARGETS,
            args=settings.NMAP_ARGS,
        )

    if scanner_type == "aws":
        from app.integrations.aws import AWSIntegration
        if db:
            try:
                from app.models import AWSConfig
                cfg = db.query(AWSConfig).first()
                if cfg and cfg.access_key_id and cfg.secret_access_key:
                    return AWSIntegration(
                        access_key_id=cfg.access_key_id,
                        secret_access_key=cfg.secret_access_key,
                        region=cfg.region or "eu-central-1",
                    )
            except Exception:
                pass
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            return AWSIntegration(
                access_key_id=settings.AWS_ACCESS_KEY_ID,
                secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region=settings.AWS_DEFAULT_REGION,
            )
        return None

    return None
