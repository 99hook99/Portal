"""
AWS integration – collects assets, vulnerabilities and CSPM findings from:
  - Direct service APIs → cloud asset inventory (does NOT require AWS Config)
  - AWS Inspector       → vulnerability findings (EC2, Lambda, ECR)
  - Security Hub        → CSPM / compliance findings

Asset discovery queries ALL enabled AWS regions automatically.
"""
import json
from typing import Optional

from app.integrations.base import BaseIntegration, VulnFinding


SEV_MAP_INSPECTOR = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
    "UNTRIAGED": "info",
}

SEV_MAP_SECURITYHUB = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}


class AWSIntegration(BaseIntegration):
    def __init__(self, access_key_id: str, secret_access_key: str, region: str):
        import boto3
        from botocore.config import Config
        self._session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region,
        )
        self._boto_config = Config(
            connect_timeout=4,
            read_timeout=8,
            retries={"max_attempts": 0},
        )
        self._home_region = region
        self._account_id: Optional[str] = None

    def _client(self, service: str, region: Optional[str] = None):
        return self._session.client(
            service,
            region_name=region or self._home_region,
            config=self._boto_config,
        )

    def _account(self) -> str:
        if not self._account_id:
            try:
                self._account_id = self._client("sts").get_caller_identity()["Account"]
            except Exception:
                self._account_id = "unknown"
        return self._account_id

    def _make_arn(self, service: str, region: str, resource_type: str, resource_id: str) -> str:
        account = self._account()
        return f"arn:aws:{service}:{region}:{account}:{resource_type}/{resource_id}"

    async def test_connection(self) -> bool:
        try:
            self._client("sts").get_caller_identity()
            return True
        except Exception:
            return False

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _get_all_regions(self) -> list[str]:
        """Return all enabled AWS regions for this account."""
        try:
            ec2 = self._client("ec2")
            resp = ec2.describe_regions(Filters=[{
                "Name": "opt-in-status",
                "Values": ["opt-in-not-required", "opted-in"],
            }])
            return [r["RegionName"] for r in resp.get("Regions", [])]
        except Exception:
            return [self._home_region]

    @staticmethod
    def _tags_to_dict(tag_list) -> dict:
        if not tag_list:
            return {}
        if isinstance(tag_list, dict):
            return tag_list
        return {t.get("Key", ""): t.get("Value", "") for t in tag_list if isinstance(t, dict)}

    def _enrich_from_tags(self, asset: dict, tags: dict) -> None:
        asset["environment"] = (
            tags.get("Environment") or tags.get("env") or tags.get("Env")
        )
        asset["owner"] = tags.get("Owner") or tags.get("owner")
        asset["business_service"] = (
            tags.get("Application") or tags.get("Service") or tags.get("Project")
        )

    def _get_account_name(self) -> str:
        """Try to get the AWS account alias (friendly name)."""
        try:
            aliases = self._client("iam").list_account_aliases().get("AccountAliases", [])
            return aliases[0] if aliases else self._account()
        except Exception:
            return self._account()

    def _base_asset(self, arn: str, name: str, asset_type: str, region: str = "") -> dict:
        return {
            "cloud_resource_id": arn,
            "identity_type": "cloud_resource",
            "location_type": "cloud",
            "source": "aws",
            "hostname": name,
            "ip_address": None,
            "os": None,
            "environment": None,
            "owner": None,
            "business_service": None,
            "internet_exposure": "unknown",
            "asset_type": asset_type,
            # cloud fields
            "region": region,
            "cloud_account_id": self._account(),
            "cloud_account_name": None,   # filled once per sync
            "instance_type": None,
            "run_state": None,
            "public_ips": None,
            "private_ips": None,
            "aws_image_id": None,
            "aws_image_name": None,
            "tags": None,                 # JSON string of all tags
        }

    # ── Per-region collectors ──────────────────────────────────────────────────

    def _collect_lambda(self, region: str) -> list[dict]:
        assets = []
        try:
            lmb = self._client("lambda", region)
            paginator = lmb.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    fn_name = fn.get("FunctionName", "")
                    fn_arn = fn.get("FunctionArn") or self._make_arn("lambda", region, "function", fn_name)
                    runtime = fn.get("Runtime") or "unknown"
                    memory = fn.get("MemorySize", "")
                    timeout = fn.get("Timeout", "")
                    state = (fn.get("State") or "Active").lower()

                    tags = {}
                    try:
                        tags = lmb.list_tags(Resource=fn_arn).get("Tags", {})
                    except Exception:
                        pass

                    asset = self._base_asset(fn_arn, fn_name, "Lambda Function", region)
                    asset["os"] = f"Lambda / {runtime}"
                    asset["internet_exposure"] = "internal"
                    asset["instance_type"] = f"{memory}MB / {timeout}s" if memory else runtime
                    asset["run_state"] = state
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_ec2(self, region: str) -> list[dict]:
        assets = []
        try:
            ec2 = self._client("ec2", region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        run_state = (inst.get("State") or {}).get("Name", "")
                        if run_state == "terminated":
                            continue

                        instance_id = inst.get("InstanceId", "")
                        arn = self._make_arn("ec2", region, "instance", instance_id)
                        tags = self._tags_to_dict(inst.get("Tags") or [])
                        name = tags.get("Name") or instance_id

                        platform = (inst.get("Platform") or "").lower()
                        os_name = "Windows" if platform == "windows" else (
                            inst.get("PlatformDetails") or "Linux"
                        )

                        # Collect all IPs from network interfaces
                        pub_ips, priv_ips = [], []
                        for ni in inst.get("NetworkInterfaces", []):
                            for assoc in ni.get("PrivateIpAddresses", []):
                                if assoc.get("PrivateIpAddress"):
                                    priv_ips.append(assoc["PrivateIpAddress"])
                                assoc2 = assoc.get("Association") or {}
                                if assoc2.get("PublicIp"):
                                    pub_ips.append(assoc2["PublicIp"])
                        if not priv_ips and inst.get("PrivateIpAddress"):
                            priv_ips = [inst["PrivateIpAddress"]]
                        if not pub_ips and inst.get("PublicIpAddress"):
                            pub_ips = [inst["PublicIpAddress"]]

                        asset = self._base_asset(arn, name, "EC2 Instance", region)
                        asset["ip_address"] = priv_ips[0] if priv_ips else None
                        asset["os"] = os_name
                        asset["internet_exposure"] = "exposed" if pub_ips else "internal"
                        asset["instance_type"] = inst.get("InstanceType")
                        asset["run_state"] = run_state
                        asset["public_ips"] = json.dumps(pub_ips) if pub_ips else None
                        asset["private_ips"] = json.dumps(priv_ips) if priv_ips else None
                        asset["aws_image_id"] = inst.get("ImageId")
                        asset["tags"] = json.dumps(tags) if tags else None
                        self._enrich_from_tags(asset, tags)
                        assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_rds(self, region: str) -> list[dict]:
        assets = []
        try:
            rds = self._client("rds", region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db.get("DBInstanceIdentifier", "")
                    arn = db.get("DBInstanceArn") or self._make_arn("rds", region, "db", db_id)
                    endpoint = db.get("Endpoint") or {}
                    hostname = endpoint.get("Address") or db_id
                    engine = db.get("Engine") or "unknown"
                    engine_ver = db.get("EngineVersion") or ""

                    tags = {}
                    try:
                        tag_resp = rds.list_tags_for_resource(ResourceName=arn)
                        tags = self._tags_to_dict(tag_resp.get("TagList", []))
                    except Exception:
                        pass

                    asset = self._base_asset(arn, hostname, "RDS Instance", region)
                    asset["os"] = f"RDS / {engine} {engine_ver}".strip()
                    asset["internet_exposure"] = (
                        "exposed" if db.get("PubliclyAccessible") else "internal"
                    )
                    asset["instance_type"] = db.get("DBInstanceClass")
                    asset["run_state"] = db.get("DBInstanceStatus")
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_ecs(self, region: str) -> list[dict]:
        assets = []
        try:
            ecs = self._client("ecs", region)
            paginator = ecs.get_paginator("list_clusters")
            cluster_arns = []
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []))

            for i in range(0, len(cluster_arns), 100):
                try:
                    resp = ecs.describe_clusters(clusters=cluster_arns[i:i + 100], include=["TAGS"])
                    for cluster in resp.get("clusters", []):
                        arn = cluster.get("clusterArn", "")
                        name = cluster.get("clusterName", arn.split("/")[-1])
                        tags = self._tags_to_dict(cluster.get("tags") or [])

                        asset = self._base_asset(arn, name, "ECS Cluster")
                        asset["os"] = "ECS Cluster"
                        self._enrich_from_tags(asset, tags)
                        assets.append(asset)
                except Exception:
                    pass
        except Exception:
            pass
        return assets

    def _collect_eks(self, region: str) -> list[dict]:
        assets = []
        try:
            eks = self._client("eks", region)
            paginator = eks.get_paginator("list_clusters")
            cluster_names = []
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))

            for name in cluster_names:
                try:
                    resp = eks.describe_cluster(name=name)
                    cluster = resp.get("cluster", {})
                    arn = cluster.get("arn") or self._make_arn("eks", region, "cluster", name)
                    version = cluster.get("version") or "unknown"
                    tags = cluster.get("tags") or {}

                    asset = self._base_asset(arn, name, "EKS Cluster", region)
                    asset["os"] = f"EKS / k8s {version}"
                    asset["run_state"] = (cluster.get("status") or "ACTIVE").lower()
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
                except Exception:
                    pass
        except Exception:
            pass
        return assets

    def _collect_load_balancers(self, region: str) -> list[dict]:
        assets = []
        # ALB / NLB
        try:
            elb = self._client("elbv2", region)
            paginator = elb.get_paginator("describe_load_balancers")
            lbs = []
            for page in paginator.paginate():
                lbs.extend(page.get("LoadBalancers", []))

            lb_arns = [lb["LoadBalancerArn"] for lb in lbs if lb.get("LoadBalancerArn")]
            tag_map: dict = {}
            for i in range(0, len(lb_arns), 20):
                try:
                    tag_resp = elb.describe_tags(ResourceArns=lb_arns[i:i + 20])
                    for td in tag_resp.get("TagDescriptions", []):
                        tag_map[td["ResourceArn"]] = self._tags_to_dict(td.get("Tags", []))
                except Exception:
                    pass

            for lb in lbs:
                arn = lb.get("LoadBalancerArn", "")
                name = lb.get("LoadBalancerName", "")
                lb_type = lb.get("Type", "application").upper()
                scheme = lb.get("Scheme", "internal")
                dns = lb.get("DNSName", "")
                tags = tag_map.get(arn, {})

                asset = self._base_asset(arn, dns or name, f"{lb_type} Load Balancer", region)
                asset["os"] = f"{lb_type} Load Balancer"
                asset["internet_exposure"] = "exposed" if scheme == "internet-facing" else "internal"
                asset["run_state"] = (lb.get("State") or {}).get("Code", "active").lower()
                asset["tags"] = json.dumps(tags) if tags else None
                self._enrich_from_tags(asset, tags)
                assets.append(asset)
        except Exception:
            pass

        # Classic ELB
        try:
            elb_c = self._client("elb", region)
            paginator = elb_c.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancerDescriptions", []):
                    name = lb.get("LoadBalancerName", "")
                    arn = self._make_arn("elasticloadbalancing", region, "loadbalancer", name)
                    dns = lb.get("DNSName", "")
                    scheme = lb.get("Scheme", "internal")

                    tags = {}
                    try:
                        tag_resp = elb_c.describe_tags(LoadBalancerNames=[name])
                        for td in tag_resp.get("TagDescriptions", []):
                            tags = self._tags_to_dict(td.get("Tags", []))
                    except Exception:
                        pass

                    asset = self._base_asset(arn, dns or name, "Classic Load Balancer", region)
                    asset["os"] = "Classic Load Balancer"
                    asset["internet_exposure"] = "exposed" if scheme == "internet-facing" else "internal"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass

        return assets

    def _collect_dynamodb(self, region: str) -> list[dict]:
        assets = []
        try:
            ddb = self._client("dynamodb", region)
            paginator = ddb.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page.get("TableNames", []):
                    arn = self._make_arn("dynamodb", region, "table", table_name)
                    tags = {}
                    try:
                        tag_resp = ddb.list_tags_of_resource(ResourceArn=arn)
                        tags = self._tags_to_dict(tag_resp.get("Tags", []))
                    except Exception:
                        pass

                    asset = self._base_asset(arn, table_name, "DynamoDB Table", region)
                    asset["os"] = "DynamoDB Table"
                    asset["internet_exposure"] = "internal"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_api_gateways(self, region: str) -> list[dict]:
        assets = []
        try:
            apigw = self._client("apigateway", region)
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    api_id = api.get("id", "")
                    name = api.get("name", api_id)
                    arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"
                    tags = api.get("tags") or {}

                    asset = self._base_asset(arn, name, "API Gateway (REST)", region)
                    asset["os"] = "API Gateway REST"
                    asset["internet_exposure"] = "exposed"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass

        try:
            apigw2 = self._client("apigatewayv2", region)
            paginator = apigw2.get_paginator("get_apis")
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    api_id = api.get("ApiId", "")
                    name = api.get("Name", api_id)
                    protocol = api.get("ProtocolType", "HTTP")
                    arn = f"arn:aws:apigateway:{region}::/apis/{api_id}"
                    tags = api.get("Tags") or {}

                    asset = self._base_asset(arn, name, f"API Gateway ({protocol})", region)
                    asset["os"] = f"API Gateway {protocol}"
                    asset["internet_exposure"] = "exposed"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass

        return assets

    def _collect_elasticache(self, region: str) -> list[dict]:
        assets = []
        try:
            ec = self._client("elasticache", region)
            paginator = ec.get_paginator("describe_cache_clusters")
            for page in paginator.paginate(ShowCacheNodeInfo=True):
                for cluster in page.get("CacheClusters", []):
                    cluster_id = cluster.get("CacheClusterId", "")
                    arn = cluster.get("ARN") or self._make_arn("elasticache", region, "cluster", cluster_id)
                    engine = cluster.get("Engine") or "unknown"
                    engine_ver = cluster.get("EngineVersion") or ""

                    tags = {}
                    try:
                        tag_resp = ec.list_tags_for_resource(ResourceName=arn)
                        tags = self._tags_to_dict(tag_resp.get("TagList", []))
                    except Exception:
                        pass

                    asset = self._base_asset(arn, cluster_id, "ElastiCache Cluster", region)
                    asset["os"] = f"ElastiCache / {engine} {engine_ver}".strip()
                    asset["internet_exposure"] = "internal"
                    asset["instance_type"] = cluster.get("CacheNodeType")
                    asset["run_state"] = cluster.get("CacheClusterStatus", "available").lower()
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_sns(self, region: str) -> list[dict]:
        assets = []
        try:
            sns = self._client("sns", region)
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    arn = topic.get("TopicArn", "")
                    name = arn.split(":")[-1] if arn else "unknown"

                    tags = {}
                    try:
                        tag_resp = sns.list_tags_for_resource(ResourceArn=arn)
                        tags = self._tags_to_dict(tag_resp.get("Tags", []))
                    except Exception:
                        pass

                    asset = self._base_asset(arn, name, "SNS Topic", region)
                    asset["os"] = "SNS Topic"
                    asset["internet_exposure"] = "internal"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_sqs(self, region: str) -> list[dict]:
        assets = []
        try:
            sqs = self._client("sqs", region)
            paginator = sqs.get_paginator("list_queues")
            for page in paginator.paginate():
                for url in page.get("QueueUrls", []):
                    name = url.split("/")[-1]
                    arn = f"arn:aws:sqs:{region}:{self._account()}:{name}"

                    tags = {}
                    try:
                        tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
                    except Exception:
                        pass

                    asset = self._base_asset(arn, name, "SQS Queue", region)
                    asset["os"] = "SQS Queue"
                    asset["internet_exposure"] = "internal"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    def _collect_secrets(self, region: str) -> list[dict]:
        assets = []
        try:
            sm = self._client("secretsmanager", region)
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    arn = secret.get("ARN", "")
                    name = secret.get("Name", arn.split(":")[-1])
                    tags = self._tags_to_dict(secret.get("Tags") or [])

                    asset = self._base_asset(arn, name, "Secrets Manager Secret", region)
                    asset["os"] = "Secrets Manager"
                    asset["internet_exposure"] = "internal"
                    asset["run_state"] = "active"
                    asset["tags"] = json.dumps(tags) if tags else None
                    self._enrich_from_tags(asset, tags)
                    assets.append(asset)
        except Exception:
            pass
        return assets

    # ── Global services (region-independent) ──────────────────────────────────

    def _collect_s3(self) -> list[dict]:
        from concurrent.futures import ThreadPoolExecutor
        assets = []
        try:
            s3 = self._client("s3")
            resp = s3.list_buckets()
            buckets = resp.get("Buckets", [])

            def _enrich_bucket(bucket) -> dict:
                name = bucket.get("Name", "")
                arn = f"arn:aws:s3:::{name}"

                bucket_region = self._home_region
                try:
                    loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                    bucket_region = loc or "us-east-1"
                except Exception:
                    pass

                tags = {}
                try:
                    tag_resp = s3.get_bucket_tagging(Bucket=name)
                    tags = self._tags_to_dict(tag_resp.get("TagSet", []))
                except Exception:
                    pass

                public = "unknown"
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    cfg = pab.get("PublicAccessBlockConfiguration", {})
                    public = "internal" if all([
                        cfg.get("BlockPublicAcls"), cfg.get("BlockPublicPolicy"),
                        cfg.get("IgnorePublicAcls"), cfg.get("RestrictPublicBuckets"),
                    ]) else "exposed"
                except Exception:
                    public = "unknown"

                asset = self._base_asset(arn, name, "S3 Bucket", bucket_region)
                asset["os"] = "S3 Bucket"
                asset["internet_exposure"] = public
                asset["run_state"] = "active"
                asset["tags"] = json.dumps(tags) if tags else None
                self._enrich_from_tags(asset, tags)
                return asset

            with ThreadPoolExecutor(max_workers=min(20, len(buckets) or 1)) as pool:
                results = list(pool.map(_enrich_bucket, buckets))
            assets = results
        except Exception:
            pass
        return assets

    def _collect_cloudfront(self) -> list[dict]:
        assets = []
        try:
            cf = self._client("cloudfront", "us-east-1")
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                dist_list = page.get("DistributionList") or {}
                for dist in dist_list.get("Items", []):
                    dist_id = dist.get("Id", "")
                    arn = dist.get("ARN") or f"arn:aws:cloudfront::{self._account()}:distribution/{dist_id}"
                    domain = dist.get("DomainName", dist_id)
                    origins = ", ".join(
                        o.get("DomainName", "")
                        for o in (dist.get("Origins") or {}).get("Items", [])
                    )

                    asset = self._base_asset(arn, domain, "CloudFront Distribution")
                    asset["os"] = f"CloudFront → {origins}" if origins else "CloudFront Distribution"
                    asset["internet_exposure"] = "exposed"
                    assets.append(asset)
        except Exception:
            pass
        return assets

    # ── Main collect_assets (multi-region, parallel) ──────────────────────────

    async def collect_assets(self) -> list[dict]:
        """
        Discover all AWS resources across ALL enabled regions in parallel.
        Uses a thread pool so all region×service combinations run concurrently.
        Does NOT require AWS Config.
        """
        import asyncio
        from concurrent.futures import ThreadPoolExecutor

        regions = self._get_all_regions()

        regional_collectors = [
            self._collect_ec2,
            self._collect_lambda,
            self._collect_rds,
            self._collect_ecs,
            self._collect_eks,
            self._collect_load_balancers,
            self._collect_dynamodb,
            self._collect_api_gateways,
            self._collect_elasticache,
            self._collect_sns,
            self._collect_sqs,
            self._collect_secrets,
        ]

        def _run_regional(collector, region) -> list[dict]:
            try:
                return collector(region)
            except Exception:
                return []

        def _run_global(collector) -> list[dict]:
            try:
                return collector()
            except Exception:
                return []

        loop = asyncio.get_event_loop()
        # Cap at 30 workers: 12 collectors × up to ~25 regions, but we don't
        # want to overwhelm the AWS API or the system.
        max_workers = min(30, len(regions) * len(regional_collectors) + 2)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            # Submit all regional tasks
            regional_futures = [
                loop.run_in_executor(pool, _run_regional, collector, region)
                for region in regions
                for collector in regional_collectors
            ]
            # Submit global tasks (S3, CloudFront)
            global_futures = [
                loop.run_in_executor(pool, _run_global, self._collect_s3),
                loop.run_in_executor(pool, _run_global, self._collect_cloudfront),
            ]

            all_results = await asyncio.gather(
                *regional_futures, *global_futures, return_exceptions=True
            )

        seen_arns: set = set()
        assets: list[dict] = []
        for batch in all_results:
            if isinstance(batch, list):
                for a in batch:
                    arn = a.get("cloud_resource_id")
                    if arn and arn not in seen_arns:
                        seen_arns.add(arn)
                        assets.append(a)

        return assets

    # ── Vulnerability findings via Inspector v2 ────────────────────────────────

    async def collect_vulns(self) -> list[VulnFinding]:
        findings = []
        try:
            inspector = self._client("inspector2")
            paginator = inspector.get_paginator("list_findings")
            filter_criteria = {
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
            }
            for page in paginator.paginate(filterCriteria=filter_criteria):
                for f in page.get("findings", []):
                    vf = self._parse_inspector_finding(f)
                    if vf:
                        findings.append(vf)
        except Exception:
            pass
        return findings

    def _parse_inspector_finding(self, f: dict) -> Optional[VulnFinding]:
        resources = f.get("resources") or []
        if not resources:
            return None

        resource = resources[0]
        arn = resource.get("id", "")
        resource_type = resource.get("type", "")
        details = resource.get("details") or {}

        ip_address = None
        hostname = arn.split(":")[-1] if arn else resource_type

        ec2 = details.get("awsEc2Instance") or {}
        if ec2:
            ips = ec2.get("ipV4Addresses") or []
            ip_address = ips[0] if ips else None

        lmb = details.get("awsLambdaFunction") or {}
        if lmb:
            hostname = lmb.get("functionName") or hostname

        sev = SEV_MAP_INSPECTOR.get((f.get("severity") or "").upper(), "info")
        title = f.get("title") or "AWS Inspector Finding"
        description = f.get("description") or None

        cve_ids = None
        cvss_score = None
        solution = None
        epss_score = None

        pkg = f.get("packageVulnerabilityDetails") or {}
        if pkg:
            vid = pkg.get("vulnerabilityId") or ""
            if vid.startswith("CVE-"):
                cve_ids = vid
            for cvss in pkg.get("cvss") or []:
                if str(cvss.get("version", "")).startswith("3"):
                    cvss_score = cvss.get("baseScore")
                    break
            if cvss_score is None:
                first = (pkg.get("cvss") or [{}])[0]
                cvss_score = first.get("baseScore")
            pkgs = pkg.get("vulnerablePackages") or []
            if pkgs:
                names = [f"{p.get('name')} {p.get('version','')}" for p in pkgs[:3]]
                fixed = [p.get("fixedInVersion") for p in pkgs if p.get("fixedInVersion")][:3]
                solution = f"Affected: {', '.join(names)}"
                if fixed:
                    solution += f". Fix: {', '.join(fixed)}"

        epss_raw = f.get("epss") or {}
        if epss_raw:
            epss_score = epss_raw.get("score")

        remediation = (f.get("remediation") or {}).get("recommendation") or {}
        if remediation.get("text") and not solution:
            solution = remediation["text"]

        plugin_id = cve_ids or (f.get("findingArn") or "").split("/")[-1] or None

        family = "AWS Inspector"
        if resource_type:
            family += f" / {resource_type.replace('AWS_', '').replace('_', ' ').title()}"

        return VulnFinding(
            title=title,
            severity=sev,
            source="aws",
            asset_ip=ip_address,
            asset_hostname=hostname,
            cloud_resource_id=arn,
            description=description,
            solution=solution,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            cve_ids=cve_ids,
            plugin_id=plugin_id,
            plugin_family=family,
            epss_score=float(epss_score) if epss_score is not None else None,
            scan_name="AWS Inspector",
        )

    # ── CSPM findings via Security Hub ─────────────────────────────────────────

    async def collect_misconfigs(self) -> list[VulnFinding]:
        findings = []
        try:
            sh = self._client("securityhub")
            paginator = sh.get_paginator("get_findings")
            filters = {
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [
                    {"Value": "NEW", "Comparison": "EQUALS"},
                    {"Value": "NOTIFIED", "Comparison": "EQUALS"},
                ],
            }
            for page in paginator.paginate(Filters=filters, MaxResults=100):
                for f in page.get("Findings", []):
                    vf = self._parse_securityhub_finding(f)
                    if vf:
                        findings.append(vf)
        except Exception:
            pass
        return findings

    def _parse_securityhub_finding(self, f: dict) -> Optional[VulnFinding]:
        resources = f.get("Resources") or []
        if not resources:
            return None

        resource = resources[0]
        arn = resource.get("Id", "")

        product_arn = f.get("ProductArn", "")
        if "inspector" in product_arn.lower():
            return None

        hostname = arn.split(":")[-1] if ":" in arn else arn

        sev = SEV_MAP_SECURITYHUB.get(
            (f.get("Severity") or {}).get("Label", "INFORMATIONAL").upper(), "info"
        )
        title = f.get("Title") or "Security Hub Finding"
        description = f.get("Description") or None

        rec = (f.get("Remediation") or {}).get("Recommendation") or {}
        solution = rec.get("Text") or None

        cvss_score = None
        for cvss in (f.get("FindingProviderFields") or {}).get("Cvss") or []:
            if str(cvss.get("Version", "")).startswith("3"):
                cvss_score = cvss.get("BaseScore")
                break

        cve_ids = None
        for vuln in f.get("Vulnerabilities") or []:
            vid = vuln.get("Id") or ""
            if vid.startswith("CVE-"):
                cve_ids = vid
                break

        if "foundational" in product_arn.lower() or "cis-aws" in product_arn.lower():
            family = "CSPM / CIS Benchmark"
        elif "patch" in product_arn.lower():
            family = "Patch Management"
        else:
            family = "Cloud Security / CSPM"

        finding_id = f.get("Id") or ""
        plugin_id = cve_ids or finding_id.split("/")[-1] or None

        return VulnFinding(
            title=title,
            severity=sev,
            source="aws",
            asset_ip=None,
            asset_hostname=hostname,
            cloud_resource_id=arn,
            description=description,
            solution=solution,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            cve_ids=cve_ids,
            plugin_id=plugin_id,
            plugin_family=family,
            scan_name="AWS Security Hub",
        )

    # ── Full sync ──────────────────────────────────────────────────────────────

    async def fetch_vulnerabilities(self) -> list[VulnFinding]:
        vulns = await self.collect_vulns()
        misconfigs = await self.collect_misconfigs()
        return vulns + misconfigs
