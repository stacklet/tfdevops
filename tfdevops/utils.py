import json
import logging
import os
import subprocess
from urllib import parse

import jmespath

DEFAULT_S3_ENCRYPT = os.environ.get("TFDEVOPS_S3_ENCRYPT", "AES256")

log = logging.getLogger("tfdevops")


def get_state_resources(tf_dir, tf_state):
    if tf_dir:
        output = subprocess.check_output(["terraform", "show", "-json"], cwd=tf_dir)
        state = json.loads(output)
    elif tf_state:
        state = json.load(open(tf_state))
    else:
        raise SyntaxError("either --module or --state-file needs to be passed")

    state_resources = {}

    resources = jmespath.search("values.root_module.resources", state) or []
    mod_resources = (
        jmespath.search("values.root_module.child_modules[].resources[]", state) or ()
    )
    resources.extend(mod_resources)

    if not resources:
        log.info("empty state")

    for r in resources:
        if r["mode"] != "managed":
            continue
        tresources = state_resources.setdefault(r["type"], [])
        tresources.append(r)
    return state_resources


def filter_empty(d):
    if isinstance(d, list):
        for v in list(d):
            if isinstance(v, dict):
                filter_empty(v)
    elif isinstance(d, dict):
        for k, v in list(d.items()):
            if not v:
                del d[k]
            elif isinstance(v, (dict, list)):
                filter_empty(v)
    return d


def write_s3_key(client, s3_path, key, content):
    kinfo = {}
    parsed = parse.urlparse(s3_path)
    kinfo["Bucket"] = parsed.netloc
    prefix = parsed.path.strip("/")
    kinfo["Key"] = "%s/%s" % (prefix, key)
    if not isinstance(content, str):
        content = json.dumps(content)
    result = client.put_object(
        Bucket=kinfo["Bucket"],
        Key=kinfo["Key"],
        # this is the default but i've seen some orgs try to force this via request policy checks
        ACL="private",
        ServerSideEncryption=DEFAULT_S3_ENCRYPT,
        Body=content,
    )
    if result.get("VersionId"):
        kinfo["Version"] = result["VersionId"]
    return kinfo


def format_s3_path(kinfo):
    t = "s3://{Bucket}/{Key}"
    if "Version" in kinfo:
        t += "?versionId={Version}"
    return t.format(**kinfo)


def format_template_url(client, s3_path):
    parsed = parse.urlparse(s3_path)
    bucket = parsed.netloc
    key = parsed.path.strip("/")
    version_id = None
    if parsed.query:
        query = parse.parse_qs(parsed.query)
        version_id = query.get("versionId", (None,))
    region = (
        client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        or "us-east-1"
    )
    url = "https://{bucket}.s3.{region}.amazonaws.com/{key}"
    if version_id:
        url += "?versionId={version_id}"
    return url.format(bucket=bucket, key=key, version_id=version_id, region=region)
