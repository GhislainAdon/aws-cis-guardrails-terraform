"""Unit tests for the NACL admin-port remediation Lambda.

Pure unittest + unittest.mock: no AWS account, no moto, no boto3 required.
"""

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import remediation  # noqa: E402  pylint: disable=wrong-import-position

PORTS = (22, 3389)


def entry(number, cidr="0.0.0.0/0", protocol="6", ports=None, action="allow", egress=False):
    e = {"RuleNumber": number, "Protocol": protocol, "RuleAction": action, "Egress": egress}
    e["Ipv6CidrBlock" if ":" in cidr else "CidrBlock"] = cidr
    if ports:
        e["PortRange"] = {"From": ports[0], "To": ports[1]}
    return e


DEFAULT_DENY = entry(32767, protocol="-1", action="deny")


def event(nacl_id="acl-0example", compliance="NON_COMPLIANT", resource_type="AWS::EC2::NetworkAcl"):
    return {
        "source": "aws.config",
        "detail-type": "Config Rules Compliance Change",
        "detail": {
            "resourceId": nacl_id,
            "resourceType": resource_type,
            "awsRegion": "eu-west-3",
            "awsAccountId": "123456789012",
            "configRuleName": "nacl-no-unrestricted-ssh-rdp",
            "newEvaluationResult": {"complianceType": compliance},
        },
    }


class ParsePortsTest(unittest.TestCase):
    def test_parses_and_sorts(self):
        self.assertEqual(remediation.parse_ports("3389, 22"), (22, 3389))

    def test_rejects_invalid(self):
        with self.assertRaises(ValueError):
            remediation.parse_ports("70000")
        with self.assertRaises(ValueError):
            remediation.parse_ports("")


class ExposedAdminPortsTest(unittest.TestCase):
    def test_ssh_open_to_world(self):
        self.assertEqual(remediation.exposed_admin_ports(entry(100, ports=(22, 22)), PORTS), (22,))

    def test_ipv6_world_is_detected(self):
        self.assertEqual(remediation.exposed_admin_ports(entry(100, "::/0", ports=(3389, 3389)), PORTS), (3389,))

    def test_all_traffic_exposes_every_admin_port(self):
        self.assertEqual(remediation.exposed_admin_ports(entry(100, protocol="-1"), PORTS), PORTS)

    def test_ignores_restricted_cidr_egress_deny_and_other_ports(self):
        self.assertEqual(remediation.exposed_admin_ports(entry(100, "10.0.0.0/8", ports=(22, 22)), PORTS), ())
        self.assertEqual(remediation.exposed_admin_ports(entry(100, ports=(22, 22), egress=True), PORTS), ())
        self.assertEqual(remediation.exposed_admin_ports(entry(100, ports=(22, 22), action="deny"), PORTS), ())
        self.assertEqual(remediation.exposed_admin_ports(entry(100, ports=(443, 443)), PORTS), ())
        self.assertEqual(remediation.exposed_admin_ports(entry(100, protocol="1"), PORTS), ())


class PlanRemediationTest(unittest.TestCase):
    def test_narrow_rule_is_deleted(self):
        actions = remediation.plan_remediation([entry(100, ports=(22, 22)), DEFAULT_DENY], PORTS)
        self.assertEqual(actions, [{"action": "delete", "rule_number": 100, "cidr": "0.0.0.0/0"}])

    def test_broad_rule_is_shadowed_by_deny_entries(self):
        actions = remediation.plan_remediation([entry(100, ports=(0, 65535)), DEFAULT_DENY], PORTS)
        self.assertEqual([a["action"] for a in actions], ["deny", "deny"])
        self.assertEqual({a["port"] for a in actions}, set(PORTS))
        self.assertTrue(all(a["rule_number"] < 100 and a["shadows"] == 100 for a in actions))

    def test_all_traffic_rule_gets_tcp_and_udp_denies(self):
        actions = remediation.plan_remediation([entry(100, protocol="-1"), DEFAULT_DENY], PORTS)
        self.assertEqual(len(actions), 4)
        self.assertEqual({(a["port"], a["protocol"]) for a in actions},
                         {(22, "6"), (22, "17"), (3389, "6"), (3389, "17")})
        self.assertEqual(len({a["rule_number"] for a in actions}), 4)

    def test_rule_numbers_never_collide_with_existing_entries(self):
        entries = [entry(n, "10.0.0.0/8", ports=(443, 443)) for n in (97, 98, 99)]
        entries.append(entry(100, ports=(1, 65535)))
        actions = remediation.plan_remediation(entries, PORTS)
        self.assertEqual(sorted(a["rule_number"] for a in actions), [95, 96])

    def test_manual_action_when_no_free_rule_number(self):
        actions = remediation.plan_remediation([entry(1, ports=(0, 65535))], PORTS)
        self.assertEqual(actions[0]["action"], "manual")

    def test_compliant_acl_needs_nothing(self):
        self.assertEqual(remediation.plan_remediation([entry(100, "10.0.0.0/8", protocol="-1"), DEFAULT_DENY], PORTS), [])


@mock.patch.dict(os.environ, {"SNS_TOPIC_ARN": "arn:aws:sns:eu-west-3:123456789012:nacl-remediation", "DRY_RUN": "false"})
class HandlerTest(unittest.TestCase):
    def _ec2(self, entries):
        ec2 = mock.Mock()
        ec2.describe_network_acls.return_value = {"NetworkAcls": [{"NetworkAclId": "acl-0example", "Entries": entries}]}
        return ec2

    def test_remediates_and_notifies(self):
        ec2, sns = self._ec2([entry(100, ports=(22, 22)), entry(110, "::/0", ports=(0, 65535)), DEFAULT_DENY]), mock.Mock()
        result = remediation.handler(event(), None, ec2=ec2, sns=sns)

        self.assertEqual(result["status"], "remediated")
        ec2.delete_network_acl_entry.assert_called_once_with(NetworkAclId="acl-0example", RuleNumber=100, Egress=False)
        self.assertEqual(ec2.create_network_acl_entry.call_count, 2)
        for call in ec2.create_network_acl_entry.call_args_list:
            self.assertEqual(call.kwargs["RuleAction"], "deny")
            self.assertEqual(call.kwargs["Ipv6CidrBlock"], "::/0")
            self.assertNotEqual(call.kwargs["RuleNumber"], 100)
        sns.publish.assert_called_once()
        self.assertIn("acl-0example", sns.publish.call_args.kwargs["Subject"])
        self.assertEqual(json.loads(sns.publish.call_args.kwargs["Message"])["status"], "remediated")

    def test_dry_run_changes_nothing(self):
        ec2, sns = self._ec2([entry(100, ports=(22, 22))]), mock.Mock()
        with mock.patch.dict(os.environ, {"DRY_RUN": "true"}):
            result = remediation.handler(event(), None, ec2=ec2, sns=sns)
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(len(result["planned_actions"]), 1)
        ec2.delete_network_acl_entry.assert_not_called()
        ec2.create_network_acl_entry.assert_not_called()
        sns.publish.assert_called_once()

    def test_ignores_compliant_or_foreign_events(self):
        ec2, sns = mock.Mock(), mock.Mock()
        self.assertEqual(remediation.handler(event(compliance="COMPLIANT"), None, ec2=ec2, sns=sns)["status"], "ignored")
        self.assertEqual(remediation.handler(event(resource_type="AWS::EC2::SecurityGroup"), None, ec2=ec2, sns=sns)["status"], "ignored")
        ec2.describe_network_acls.assert_not_called()
        sns.publish.assert_not_called()

    def test_missing_acl(self):
        ec2, sns = mock.Mock(), mock.Mock()
        ec2.describe_network_acls.return_value = {"NetworkAcls": []}
        self.assertEqual(remediation.handler(event(), None, ec2=ec2, sns=sns)["status"], "not_found")


if __name__ == "__main__":
    unittest.main()
