"""Regression contracts on pure transforms, with network/process calls blocked."""
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'demo'))
from policy_demo import fixture, load_updater, exercise

class PolicyUpdateTests(unittest.TestCase):
    def setUp(self):
        self.steam=load_updater('update-steam-direct.py')
        self.torrent=load_updater('update-torrent-direct.py')
        self.wechat=load_updater('update-wechat-direct.py')
        self.before=fixture()

    def transform(self,updater,data=None):
        original=yaml.safe_dump(self.before if data is None else data,sort_keys=False)
        with mock.patch('subprocess.run',side_effect=AssertionError('No child processes allowed')), \
             mock.patch('urllib.request.build_opener',side_effect=AssertionError('No network allowed')):
            return updater.transform(original)

    def test_steam_adds_only_owned_rules_and_preserves_original_order(self):
        _,after=self.transform(self.steam)
        self.assertEqual(after['rules'],self.steam.RULES+self.before['rules'])
        self.assertEqual({k:v for k,v in after.items() if k!='rules'},
                         {k:v for k,v in self.before.items() if k!='rules'})

    def test_steam_idempotent(self):
        text,after=self.transform(self.steam)
        self.assertEqual(self.steam.transform(text),(text,after))

    def test_steam_keeps_unknown_udp_rejected_and_does_not_globally_open_stun(self):
        _,after=self.transform(self.steam)
        limit=after['rules'].index('NETWORK,UDP,REJECT')
        self.assertTrue(all(after['rules'].index(r)<limit for r in self.steam.RULES))
        self.assertFalse(any('DST-PORT,3478' in r for r in self.steam.RULES))
        self.assertEqual(after['rules'][-1],'MATCH,DEMO-EXIT')

    def test_steam_rejects_missing_udp_guard(self):
        data=copy.deepcopy(self.before)
        data['rules'].remove('NETWORK,UDP,REJECT')
        with self.assertRaises(ValueError):self.transform(self.steam,data)

    def test_steam_rejects_disabled_process_lookup(self):
        data=copy.deepcopy(self.before);data['find-process-mode']='off'
        with self.assertRaises(ValueError):self.transform(self.steam,data)

    def test_torrent_preserves_dns_nodes_and_rule_tail(self):
        _,after=self.transform(self.torrent)
        self.assertEqual(after['rules'],self.torrent.RULES+self.before['rules'])
        self.assertEqual(after['dns'],self.before['dns'])
        self.assertEqual(after['proxies'],self.before['proxies'])

    def test_torrent_idempotent(self):
        text,after=self.transform(self.torrent)
        self.assertEqual(self.torrent.transform(text),(text,after))

    def test_torrent_requires_independent_direct_dns(self):
        data=copy.deepcopy(self.before);data['dns'].pop('direct-nameserver')
        with self.assertRaises(ValueError):self.transform(self.torrent,data)

    def test_wechat_is_additive_and_idempotent(self):
        text,after=self.transform(self.wechat)
        self.assertEqual(after['rules'],self.wechat.RULES+self.before['rules'])
        self.assertEqual(self.wechat.transform(text),(text,after))

    def test_wechat_preserves_indented_sequence(self):
        class IndentedDumper(yaml.SafeDumper):
            def increase_indent(self,flow=False,indentless=False):
                return super().increase_indent(flow,False)
        original=yaml.dump(self.before,Dumper=IndentedDumper,sort_keys=False)
        text,after=self.wechat.transform(original)
        self.assertIn('rules:\n  #',text)
        self.assertEqual(after['rules'],self.wechat.RULES+self.before['rules'])
        self.assertEqual({k:v for k,v in after.items() if k!='rules'},
                         {k:v for k,v in self.before.items() if k!='rules'})

    def test_wechat_preserves_fields_after_rules(self):
        data=copy.deepcopy(self.before);data['later-field']={'preserve':True}
        _,after=self.transform(self.wechat,data)
        self.assertEqual(after['later-field'],data['later-field'])

    def test_trailing_non_rule_field_is_rejected_by_steam_transform(self):
        # The narrow serializer must not silently remove later config fields.
        data=copy.deepcopy(self.before);data['later-field']={'preserve':True}
        with self.assertRaises(ValueError):self.transform(self.steam,data)

    def test_sanitized_daily_policy_retains_unknown_udp_guard(self):
        policy=yaml.safe_load((ROOT/'examples/mihomo/daily.yaml.example').read_text(encoding='utf-8'))
        self.assertEqual(len(policy['rules']),531)
        self.assertEqual(policy['rules'][-2],'NETWORK,UDP,REJECT')
        self.assertTrue(all(str(n.get('password','EXAMPLE_')).startswith('EXAMPLE_') for n in policy['proxies']))

    def test_offline_demo_reports_invariants(self):
        result=exercise()
        for key in ['original_rules_in_order','other_fields_unchanged','idempotent','unknown_udp_rejected']:
            self.assertTrue(result[key])
        self.assertFalse(result['network_or_service_operations_performed'])

if __name__=='__main__':unittest.main()
