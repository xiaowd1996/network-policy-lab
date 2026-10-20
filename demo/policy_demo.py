"""Exercise a real pure policy transform on synthetic data; never deploy."""
import importlib.util
import json
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]

def load_updater(name):
    path=ROOT/'reference/maintenance'/name
    spec=importlib.util.spec_from_file_location('demo_'+path.stem.replace('-','_'),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def fixture():
    # A direct placeholder makes it clear this is not a real proxy node.
    return {
        'mode':'rule',
        'find-process-mode':'always',
        'dns':{'enable':True,'direct-nameserver':['223.5.5.5']},
        'proxies':[{'name':'DEMO','type':'direct'}],
        'proxy-groups':[{'name':'DEMO-EXIT','type':'select','proxies':['DEMO']}],
        # rules is intentionally last, matching the updater's input contract.
        'rules':['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
                 'DOMAIN-SUFFIX,example.invalid,DEMO-EXIT',
                 'NETWORK,UDP,REJECT','MATCH,DEMO-EXIT']
    }

def exercise():
    updater=load_updater('update-steam-direct.py')
    before=fixture()
    original=yaml.safe_dump(before,sort_keys=False)
    updated,after=updater.transform(original)
    repeated,again=updater.transform(updated)
    return {
        'mode':'offline_in_memory_transform',
        'original_rule_count':len(before['rules']),
        'result_rule_count':len(after['rules']),
        'added_rules':len(updater.RULES),
        'original_rules_in_order':after['rules'][len(updater.RULES):]==before['rules'],
        'other_fields_unchanged':{k:v for k,v in after.items() if k!='rules'}=={k:v for k,v in before.items() if k!='rules'},
        'idempotent':updated==repeated and after==again,
        'unknown_udp_rejected':'NETWORK,UDP,REJECT' in after['rules'],
        'network_or_service_operations_performed':False
    }

if __name__=='__main__':
    print(json.dumps(exercise(),indent=2))
