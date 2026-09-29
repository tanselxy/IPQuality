"""Offline regression tests: load only mail functions and mock all network tools."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "ip.sh").read_text()
BASH = "/opt/homebrew/bin/bash" if Path("/opt/homebrew/bin/bash").exists() else shutil.which("bash")
FUNCTIONS = SOURCE[SOURCE.index("get_sorted_mx_records(){\n"):SOURCE.index("check_dnsbl_parallel(){\n")]
MAIL_JSON = SOURCE[SOURCE.index('mail_updates+=".Mail |= . + { Port25:'):SOURCE.index('ipjson=$(echo "$ipjson"|jq')]

MOCKS = r'''
declare -A smail smailstatus smail_reason sinfo
IP=198.51.100.2
YY=${TEST_LANGUAGE:-cn}
usePROXY=''
[[ $TEST_CASE == proxy ]]&&usePROXY='http://proxy.test'
smail[t]=423;smail[c]=421;smail[m]=2;smail[b]=0
show_progress_bar(){ :; }
kill_progress_bar(){ :; }
disown(){ :; }
ss(){ printf 'unexpected ss\n' >>"$TEST_LOG"; return 70; }
ip(){
 if [[ $TEST_CASE == local_source ]];then
  printf '1: eth0 inet 198.51.100.2/24\n'
 else
  printf '1: eth0 inet 192.0.2.100/24\n'
 fi
}
timeout(){ shift; "$@"; }
dig(){
 local kind=${@: -2:1} host=${@: -1}
 if [[ $TEST_CASE == dns_failure ]];then return 9;fi
 if [[ $kind == MX ]];then
  [[ $TEST_CASE == no_mx ]]&&return 0
  printf '20 backup.%s.\n10 primary.%s.\n30 third.%s.\n40 fourth.%s.\n' "$host" "$host" "$host" "$host"
 elif [[ $kind == AAAA ]];then
  [[ $TEST_CASE == no_ipv6 || $TEST_CASE == dual_stack ]]&&return 0
  printf '2001:db8::2\n'
 elif [[ $kind == A ]];then
  if [[ $TEST_CASE == mixed && $host == *yahoo.com* ]];then return 9;fi
  if [[ $TEST_CASE == alternate && $host == primary.* ]];then
   printf '192.0.2.3\n'
  elif [[ $TEST_CASE == mixed && $host == *outlook.com* ]];then
   printf '192.0.2.3\n'
  else
   printf 'alias.example.test.\n192.0.2.2\n'
  fi
 fi
}
nc(){
 printf '%s\n' "$*" >>"$TEST_LOG"
 [[ "$*" == *smtp.mailgun.org* ]]&&{ printf 'unexpected baseline'; return 71; }
 case "$TEST_CASE:$*" in
  blocked:*) printf 'Connection timed out';return 124;;
  unsupported:*) printf 'invalid option -- 6';return 2;;
  *192.0.2.3*) printf 'Connection refused';return 1;;
 esac
 return 0
}
save_mail(){
 local mail_updates='' reason_json
 ipjson='{"Mail":{},"Score":{"AbuseIPDB":0}}'
'''


def run_case(case, family=4, language="cn"):
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "probes.log"
        env = {**os.environ, "TEST_CASE": case, "TEST_LANGUAGE": language, "TEST_LOG": str(log)}
        command = FUNCTIONS + MOCKS + MAIL_JSON + '\nprintf "%s\\n" "$ipjson"|jq "$mail_updates."\n}\n'
        command += f"check_mail {family}\nsave_mail\n"
        if case == "dual_stack":
            command += "IP=2001:db8::9\ncheck_mail 6\nsave_mail\n"
        result = subprocess.run([BASH, "-c", command], env=env, capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise AssertionError(result.stderr)
        # Compact before splitting consecutive IPv4 / IPv6 objects.
        decoder = json.JSONDecoder()
        text = result.stdout.strip()
        reports = []
        while text:
            report, end = decoder.raw_decode(text)
            reports.append(report)
            text = text[end:].strip()
        return reports, log.read_text() if log.exists() else ""


class MailRegressionTests(unittest.TestCase):
    def test_local_listener_and_old_baseline_do_not_control_results(self):
        reports, log = run_case("listener")
        self.assertTrue(reports[0]["Mail"]["Port25"])
        self.assertTrue(reports[0]["Mail"]["Gmail"])
        self.assertNotIn("ss", log)
        self.assertNotIn("mailgun", log)
        self.assertNotIn("-p25", log)

    def test_service_results_and_dns_blacklist_are_independent(self):
        reports, _ = run_case("mixed")
        mail = reports[0]["Mail"]
        self.assertIs(mail["Port25"], True)
        self.assertIs(mail["Gmail"], True)
        self.assertIs(mail["Outlook"], False)
        self.assertIsNone(mail["Yahoo"])
        self.assertEqual(mail["Diagnostics"]["Outlook"], "连接被拒绝")
        self.assertEqual(mail["Diagnostics"]["Yahoo"], "邮件服务器 DNS 查询失败")
        self.assertEqual(mail["DNSBlacklist"], {"Total": 423, "Clean": 421, "Marked": 2, "Blacklisted": 0})
        self.assertEqual(reports[0]["Score"], {"AbuseIPDB": 0})

    def test_nat_does_not_bind_public_ip_but_local_source_can_be_bound(self):
        _, nat_log = run_case("nat")
        _, local_log = run_case("local_source")
        self.assertNotIn("-s ", nat_log)
        self.assertIn("-s 198.51.100.2", local_log)
        self.assertNotIn("-p25", local_log)

    def test_alternate_mx_is_tried_after_primary_fails(self):
        reports, log = run_case("alternate")
        self.assertIs(reports[0]["Mail"]["Gmail"], True)
        self.assertIn("192.0.2.3 25", log)
        self.assertIn("192.0.2.2 25", log)

    def test_ipv6_uses_ipv6_and_does_not_inherit_ipv4_results(self):
        reports, log = run_case("ipv6", 6)
        self.assertIs(reports[0]["Mail"]["Port25"], True)
        self.assertIn("-6 -z -w4 2001:db8::2 25", log)
        self.assertNotIn("192.0.2.", log)
        dual, _ = run_case("dual_stack")
        self.assertIs(dual[0]["Mail"]["Gmail"], True)
        self.assertIsNone(dual[1]["Mail"]["Gmail"])
        self.assertEqual(dual[1]["Mail"]["Diagnostics"]["Gmail"], "邮件服务器未提供 IPv6 地址")

    def test_known_connection_failure_is_distinct_from_unknown(self):
        blocked, _ = run_case("blocked")
        self.assertIs(blocked[0]["Mail"]["Port25"], False)
        self.assertEqual(blocked[0]["Mail"]["Diagnostics"]["Gmail"], "连接超时")
        for case, family in [("dns_failure", 4), ("no_mx", 4), ("no_ipv6", 6), ("unsupported", 6), ("proxy", 4)]:
            with self.subTest(case=case):
                reports, _ = run_case(case, family)
                self.assertIsNone(reports[0]["Mail"]["Port25"])
                self.assertIsNone(reports[0]["Mail"]["Gmail"])
                self.assertTrue(reports[0]["Mail"]["Diagnostics"]["Gmail"])

    def test_english_reason_is_preserved(self):
        reports, _ = run_case("blocked", language="en")
        self.assertEqual(reports[0]["Mail"]["Diagnostics"]["Gmail"], "Connection timed out")


if __name__ == "__main__":
    unittest.main()
