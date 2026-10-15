"""Auto-remediation for the AWS Config rule NACL_NO_UNRESTRICTED_SSH_RDP.

Triggered by an EventBridge "Config Rules Compliance Change" event when a
network ACL becomes NON_COMPLIANT. For every inbound ALLOW entry open to the
world (0.0.0.0/0 or ::/0) that reaches an administration port (22, 3389):

* if the entry only covers administration ports, it is deleted;
* if the entry is broader (all traffic, or a wide port range), deleting it
  could cut legitimate traffic, so explicit DENY entries for the administration
  ports are inserted *before* it (lower rule number) instead.

A summary is always published to SNS. Set DRY_RUN=true to only report.
"""

import json
import logging
import os

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
PROTO_ALL, PROTO_TCP, PROTO_UDP = "-1", "6", "17"

_CLIENTS = {}


def _client(service, region=None):
    """Create boto3 clients lazily so unit tests never need boto3 or AWS."""
    key = (service, region)
    if key not in _CLIENTS:
        import boto3  # pylint: disable=import-outside-toplevel

        _CLIENTS[key] = boto3.client(service, region_name=region)
    return _CLIENTS[key]


def parse_ports(raw):
    """Parse "22,3389" into a sorted tuple of ints."""
    ports = sorted({int(p) for p in str(raw).split(",") if p.strip()})
    if not ports or any(p < 0 or p > 65535 for p in ports):
        raise ValueError(f"invalid ADMIN_PORTS value: {raw!r}")
    return tuple(ports)


def _cidr(entry):
    return entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")


def exposed_admin_ports(entry, admin_ports):
    """Return the admin ports that an inbound NACL entry opens to the world."""
    if entry.get("Egress") or entry.get("RuleAction") != "allow":
        return ()
    if _cidr(entry) not in WORLD_CIDRS:
        return ()
    protocol = str(entry.get("Protocol"))
    if protocol == PROTO_ALL:
        return tuple(admin_ports)
    if protocol not in (PROTO_TCP, PROTO_UDP):
        return ()
    port_range = entry.get("PortRange")
    if not port_range:
        return tuple(admin_ports)
    low, high = port_range.get("From", 0), port_range.get("To", 65535)
    return tuple(p for p in admin_ports if low <= p <= high)


def _only_admin_ports(entry, exposed):
    """True when deleting the entry cannot remove anything but admin ports."""
    if str(entry.get("Protocol")) == PROTO_ALL:
        return False
    port_range = entry.get("PortRange") or {}
    low, high = port_range.get("From", 0), port_range.get("To", 65535)
    return high - low + 1 == len(exposed)


def plan_remediation(entries, admin_ports):
    """Compute the actions needed for one NACL. Pure function (no AWS calls)."""
    used = {e["RuleNumber"] for e in entries if not e.get("Egress")}
    actions = []

    offending = sorted(
        (e for e in entries if exposed_admin_ports(e, admin_ports)),
        key=lambda e: e["RuleNumber"],
    )
    for entry in offending:
        exposed = exposed_admin_ports(entry, admin_ports)
        cidr = _cidr(entry)
        if _only_admin_ports(entry, exposed):
            actions.append({"action": "delete", "rule_number": entry["RuleNumber"], "cidr": cidr})
            continue

        protocols = (PROTO_TCP, PROTO_UDP) if str(entry.get("Protocol")) == PROTO_ALL else (str(entry["Protocol"]),)
        needed = [(port, proto) for port in exposed for proto in protocols]
        free = [n for n in range(entry["RuleNumber"] - 1, 0, -1) if n not in used][: len(needed)]
        if len(free) < len(needed):
            actions.append({"action": "manual", "rule_number": entry["RuleNumber"], "cidr": cidr,
                            "reason": "no free rule number below the offending entry"})
            continue
        for number, (port, proto) in zip(free, needed):
            used.add(number)
            actions.append({"action": "deny", "rule_number": number, "cidr": cidr,
                            "protocol": proto, "port": port, "shadows": entry["RuleNumber"]})
    return actions


def apply_actions(ec2, nacl_id, actions, dry_run):
    """Execute the planned actions against EC2. Returns the executed actions."""
    done = []
    for act in actions:
        if act["action"] == "manual" or dry_run:
            continue
        cidr_key = "Ipv6CidrBlock" if ":" in act["cidr"] else "CidrBlock"
        if act["action"] == "delete":
            ec2.delete_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=act["rule_number"], Egress=False)
        elif act["action"] == "deny":
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=act["rule_number"],
                Protocol=act["protocol"],
                RuleAction="deny",
                Egress=False,
                PortRange={"From": act["port"], "To": act["port"]},
                **{cidr_key: act["cidr"]},
            )
        done.append(act)
    return done


def handler(event, _context, ec2=None, sns=None):
    """Lambda entry point."""
    detail = event.get("detail", {})
    nacl_id = detail.get("resourceId")
    compliance = detail.get("newEvaluationResult", {}).get("complianceType")
    if detail.get("resourceType") != "AWS::EC2::NetworkAcl" or compliance != "NON_COMPLIANT" or not nacl_id:
        LOGGER.info("Ignoring event: %s", json.dumps(detail)[:500])
        return {"status": "ignored"}

    region = detail.get("awsRegion")
    admin_ports = parse_ports(os.environ.get("ADMIN_PORTS", "22,3389"))
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    ec2 = ec2 or _client("ec2", region)
    sns = sns or _client("sns")

    nacls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"]
    if not nacls:
        return {"status": "not_found", "network_acl_id": nacl_id}

    actions = plan_remediation(nacls[0]["Entries"], admin_ports)
    done = apply_actions(ec2, nacl_id, actions, dry_run)
    status = "dry_run" if dry_run else ("manual_action_required" if any(a["action"] == "manual" for a in actions) else "remediated")

    summary = {
        "status": status,
        "network_acl_id": nacl_id,
        "account": detail.get("awsAccountId"),
        "region": region,
        "config_rule": detail.get("configRuleName"),
        "planned_actions": actions,
        "applied_actions": done,
    }
    LOGGER.info(json.dumps(summary))
    sns.publish(
        TopicArn=os.environ["SNS_TOPIC_ARN"],
        Subject=f"[CIS] NACL admin port exposure - {nacl_id} - {status}"[:100],
        Message=json.dumps(summary, indent=2),
    )
    return summary
