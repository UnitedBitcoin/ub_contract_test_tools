# coding: utf-8
from __future__ import print_function
import json
import requests
import random
import unittest
from btcscriptencoder import *

config = {
    'HOST': '192.168.1.148',
    'PORT': 60011,
    'MAIN_USER_ADDRESS': '1CMvrM73nfGwwRTnZvhroyY2CSPgsK1wt1',
    'OTHER_USER_ADDRESS': '1MPd4YVHB5LCanrkTf6JqzMBBZvnMpUdLc',
    'PRECISION': 100000000,
    'CONTRACT_VERSION': b'\x01',
}

other_addr = config['OTHER_USER_ADDRESS']

headers = {
    'content-type': 'application/json',
    'Authorization': 'Basic YTph',
}


def call_rpc(method, params):
    url = "http://%s:%d/" % (config['HOST'], config['PORT'])
    payload = {
        'method': method,
        'params': params,
        "jsonrpc": "2.0",
        "id": 0,
    }
    res = requests.post(url, data=json.dumps(payload), headers=headers)
    if res.status_code != 200 and res.text == '':
        raise Exception(res.reason)
    res = res.json()
    if res.get('error'):
        print(method, params)
        raise Exception(res.get('error'))
    return res['result']


created_contract_addr = 'CONQJytkzZGgJmAdkDsKeT3tW1EVFB4kBtX1'

using_utxos = []


def get_utxo(caller_addr=None):
    if caller_addr is None:
        caller_addr = config['MAIN_USER_ADDRESS']
    utxos = call_rpc('listunspent', [])
    having_amount_items = list(filter(lambda x: x.get('address', None) == caller_addr and int(x.get('amount')) > 40,
                                      utxos))

    def in_using(item):
        for utxo in using_utxos:
            if utxo['txid'] == item['txid'] and utxo['vout'] == item['vout']:
                return True
        return False

    not_used_items = filter(lambda x: not in_using(x), having_amount_items)
    utxo = next(not_used_items)
    using_utxos.append(utxo)
    return utxo


def invoke_contract_api(caller_addr, contract_addr, api_name, api_arg, withdraw_infos=None, withdraw_froms=None):
    utxo = get_utxo(caller_addr)
    call_contract_script = CScript(
        [config['CONTRACT_VERSION'], api_arg.encode('utf8'), api_name.encode('utf8'), contract_addr.encode("utf8"),
         caller_addr.encode('utf8'),
         5000, 40, OP_CALL])
    call_contract_script_hex = call_contract_script.hex()
    fee = 0.01
    vouts = {
        caller_addr: '%.6f' % (utxo['amount'] - fee),
        'contract': call_contract_script_hex,
    }
    if withdraw_infos is None:
        withdraw_infos = {}
    for k, v in withdraw_infos.items():
        if k == caller_addr:
            vouts[k] = "%.6f" % (float(vouts[k]) + v)
        else:
            vouts[k] = "%.6f" % v
    if withdraw_froms is None:
        withdraw_froms = {}
    spend_contract_all_script_hexs = []
    for withdraw_from_contract_addr, withdraw_amount in withdraw_froms.items():
        spend_contract_script = CScript([
            int(withdraw_amount * config['PRECISION']), withdraw_from_contract_addr.encode('utf8'), OP_SPEND
        ])
        spend_contract_script_hex = spend_contract_script.hex()
        spend_contract_all_script_hexs.append(spend_contract_script_hex)
    if len(spend_contract_all_script_hexs) > 0:
        vouts['spend_contract'] = spend_contract_all_script_hexs
    call_contract_raw_tx = call_rpc('createrawtransaction', [
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
            },
        ],
        vouts,
    ])
    signed_call_contract_raw_tx_res = call_rpc('signrawtransaction', [
        call_contract_raw_tx,
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
                'scriptPubKey': utxo['scriptPubKey'],
            },
        ],
    ])
    assert (signed_call_contract_raw_tx_res.get('complete', None) is True)
    signed_call_contract_raw_tx = signed_call_contract_raw_tx_res.get('hex')
    res = call_rpc('sendrawtransaction', [signed_call_contract_raw_tx])
    return res


def generate_block(miner=None):
    if miner is None:
        miner = config['MAIN_USER_ADDRESS']
    return call_rpc('generatetoaddress', [
        1, miner, 1000000,
    ])


def create_new_contract(contract_bytecode_path):
    utxo = get_utxo()
    bytecode_hex = read_contract_bytecode_hex(contract_bytecode_path)
    register_contract_script = CScript(
        [config['CONTRACT_VERSION'], bytes().fromhex(bytecode_hex), config['MAIN_USER_ADDRESS'].encode('utf8'), 5000,
         40, OP_CREATE])
    create_contract_script = register_contract_script.hex()
    create_contract_raw_tx = call_rpc('createrawtransaction', [
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
            },
        ],
        {
            config['MAIN_USER_ADDRESS']: '%.6f' % (utxo['amount'] - 0.01),
            'contract': create_contract_script,
        },
    ])
    signed_create_contract_raw_tx_res = call_rpc('signrawtransaction', [
        create_contract_raw_tx,
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
                'scriptPubKey': utxo['scriptPubKey'],
            },
        ],
    ])
    assert (signed_create_contract_raw_tx_res.get('complete', None) is True)
    signed_create_contract_raw_tx = signed_create_contract_raw_tx_res.get('hex')
    call_rpc('sendrawtransaction', [signed_create_contract_raw_tx])
    contract_addr = call_rpc('getcreatecontractaddress', [
        signed_create_contract_raw_tx
    ])
    return contract_addr['address']


def upgrade_contract(contract_addr, contract_name, contract_desc, caller_addr=None):
    if caller_addr is None:
        caller_addr = config['MAIN_USER_ADDRESS']
    utxo = get_utxo(caller_addr)
    call_contract_script = CScript(
        [config['CONTRACT_VERSION'], contract_desc.encode("utf8"), contract_name.encode("utf8"),
         contract_addr.encode("utf8"),
         caller_addr.encode('utf8'),
         5000, 40, OP_UPGRADE])
    call_contract_script_hex = call_contract_script.hex()
    fee = 0.01
    call_contract_raw_tx = call_rpc('createrawtransaction', [
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
            },
        ],
        {
            config['MAIN_USER_ADDRESS']: "%.6f" % (utxo['amount'] - fee,),
            'contract': call_contract_script_hex,
        },
    ])
    signed_call_contract_raw_tx_res = call_rpc('signrawtransaction', [
        call_contract_raw_tx,
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
                'scriptPubKey': utxo['scriptPubKey'],
            },
        ],
    ])
    assert (signed_call_contract_raw_tx_res.get('complete', None) is True)
    signed_call_contract_raw_tx = signed_call_contract_raw_tx_res.get('hex')
    call_rpc('sendrawtransaction', [signed_call_contract_raw_tx])


def deposit_to_contract(caller_addr, contract_addr, deposit_amount, deposit_memo=" "):
    utxo = get_utxo()
    call_contract_script = CScript(
        [config['CONTRACT_VERSION'], deposit_memo.encode('utf8'), int(deposit_amount * config['PRECISION']),
         contract_addr.encode("utf8"),
         caller_addr.encode('utf8'),
         5000, 40, OP_DEPOSIT_TO_CONTRACT])
    call_contract_script_hex = call_contract_script.hex()
    call_contract_raw_tx = call_rpc('createrawtransaction', [
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
            },
        ],
        {
            config['MAIN_USER_ADDRESS']: '%.6f' % (utxo['amount'] - deposit_amount - 0.01),
            'contract': call_contract_script_hex,
        },
    ])
    signed_call_contract_raw_tx_res = call_rpc('signrawtransaction', [
        call_contract_raw_tx,
        [
            {
                'txid': utxo['txid'],
                'vout': utxo['vout'],
                'scriptPubKey': utxo['scriptPubKey'],
            },
        ],
    ])
    assert (signed_call_contract_raw_tx_res.get('complete', None) is True)
    signed_call_contract_raw_tx = signed_call_contract_raw_tx_res.get('hex')
    return call_rpc('sendrawtransaction', [signed_call_contract_raw_tx])


class UbtcContractTests(unittest.TestCase):
    def test_create_contract(self):
        print("test_create_contract")
        new_contract_addr = create_new_contract("./test.gpc")
        generate_block()
        print("new contract address: %s" % new_contract_addr)
        return new_contract_addr

    def test_get_contract_info(self):
        print("test_get_contract_info")
        contract_addr = created_contract_addr
        contract_info = call_rpc('getcontractinfo', [contract_addr])
        print(contract_info)
        self.assertEqual(contract_info['id'], contract_addr)
        if len(contract_info['name']) > 0:
            contract_info_found_by_name = call_rpc('getcontractinfo', [contract_info['name']])
            print("contract_info_found_by_name: ", contract_info_found_by_name)

    def test_get_simple_contract_info(self):
        print("test_get_simple_contract_info")
        contract_addr = created_contract_addr
        contract_info = call_rpc('getsimplecontractinfo', [contract_addr])
        print(contract_info)
        self.assertEqual(contract_info['id'], contract_addr)

    def test_get_current_root_state_hash(self):
        print("test_get_current_root_state_hash")
        root_state_hash = call_rpc('currentrootstatehash', [])
        print("current root_state_hash: ", root_state_hash)
        height = call_rpc('getblockcount', [])
        self.test_call_contract_api()
        mine_res = call_rpc('generatetoaddress', [
            1, config['MAIN_USER_ADDRESS'], 1000000,
        ])
        new_root_state_hash = call_rpc('currentrootstatehash', [])
        old_root_state_hash = call_rpc('blockrootstatehash', [height])
        print("new_root_state_hash: %s, old_root_state_hash: %s" % (new_root_state_hash, old_root_state_hash))
        self.assertEqual(old_root_state_hash, root_state_hash)

    def test_call_contract_query_storage(self):
        print("test_call_contract_query_storage")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        invoke_res = call_rpc('invokecontractoffline', [
            config['MAIN_USER_ADDRESS'], contract_addr, "query", "",
        ])
        print("invoke result: ", invoke_res)
        self.assertEqual(invoke_res.get('result'), 'hello')
        print("gas used: ", invoke_res.get('gasCount'))
        self.assertTrue(invoke_res.get('gasCount') > 0)

    def test_call_contract_once_api(self):
        print("test_call_contract_once_api")
        contract_addr = created_contract_addr
        try:
            invoke_contract_api(config['MAIN_USER_ADDRESS'], contract_addr, "once", " ")
            invoke_contract_api(config['MAIN_USER_ADDRESS'], contract_addr, "once", " ")
            mine_res = generate_block()
            print("mine res: ", mine_res)
            self.assertTrue(False)
        except Exception as e:
            print(e)
            pass

    def test_call_contract_offline(self):
        print("test_call_contract_offline")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        invoke_res = call_rpc('invokecontractoffline', [
            config['MAIN_USER_ADDRESS'], contract_addr, "query", "abc",
        ])
        print("invoke result: ", invoke_res)
        print("gas used: ", invoke_res.get('gasCount'))
        self.assertTrue(invoke_res.get('gasCount') > 0)
        self.assertEqual(invoke_res.get('result'), 'hello')

    def test_import_contract_by_address(self):
        print("test_import_contract_by_address")
        contract_addr = created_contract_addr
        invoke_res = call_rpc('invokecontractoffline', [
            config['MAIN_USER_ADDRESS'], contract_addr, "import_contract_by_address_demo", "%s" % contract_addr,
        ])
        print("invoke result: ", invoke_res)
        print("gas used: ", invoke_res.get('gasCount'))
        self.assertTrue(invoke_res.get('gasCount') > 0)
        self.assertEqual('hello world', invoke_res['result'])

    def test_register_contract_testing(self):
        print("test_register_contract_testing")
        bytecode_hex = read_contract_bytecode_hex("./test.gpc")
        invoke_res = call_rpc('registercontracttesting', [
            config['MAIN_USER_ADDRESS'], bytecode_hex,
        ])
        print("register contract testing result: ", invoke_res)
        print("gas used: ", invoke_res.get('gasCount'))
        self.assertTrue(invoke_res.get('gasCount') > 0)

    def test_upgrade_contract_testing(self):
        print("test_upgrade_contract_testing")
        contract_addr = self.test_create_contract()
        contract_name = "contract_name_%d" % random.randint(1, 99999999)
        invoke_res = call_rpc('upgradecontracttesting', [
            config['MAIN_USER_ADDRESS'], contract_addr, contract_name, 'test contract desc',
        ])
        print("upgrade contract testing result: ", invoke_res)
        print("gas used: ", invoke_res.get('gasCount'))
        self.assertTrue(invoke_res.get('gasCount') > 0)

    def test_deposit_to_contract_testing(self):
        print("test_deposit_to_contract_testing")
        invoke_res = call_rpc('deposittocontracttesting', [
            config['MAIN_USER_ADDRESS'], created_contract_addr, 10, 'this is deposit memo',
        ])
        print("deposit to contract testing result: ", invoke_res)
        print("gas used: ", invoke_res.get('gasCount'))
        self.assertTrue(invoke_res.get('gasCount') > 0)

    def test_get_transaction_contract_events(self):
        print("test_get_transaction_contract_events")
        invoke_res = call_rpc('gettransactionevents', [
            '939421f700919cf1388c63c3e7dbfd79db432f9aa6e1e388bd31f42ed20025cb',
        ])
        print("contract events result: ", invoke_res)

    def test_call_contract_api(self):
        print("test_call_contract_api")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        invoke_contract_api(config['MAIN_USER_ADDRESS'], contract_addr, "hello", "abc")
        mine_res = call_rpc('generatetoaddress', [
            1, config['MAIN_USER_ADDRESS'], 1000000,
        ])
        print("mine res: ", mine_res)

    def test_call_error_contract_api(self):
        print("test_call_error_contract_api")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        try:
            invoke_contract_api(config['MAIN_USER_ADDRESS'], contract_addr, "error",
                                " ")  # can't use empty string as api argument
            self.assertTrue(False)
        except Exception as e:
            print(e)
            print("error invoke contract passed successfully")

    def deposit_to_contract(self, mine=True):
        print("deposit_to_contract")
        caller_addr = config['MAIN_USER_ADDRESS']
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        deposit_amount1 = 0.1
        deposit_to_contract(caller_addr, contract_addr, deposit_amount1, "memo123")
        # put another tx again
        deposit_to_contract(caller_addr, contract_addr, 0.2, "memo1234")
        if mine:
            mine_res = call_rpc('generatetoaddress', [
                1, config['MAIN_USER_ADDRESS'], 1000000,
            ])
            print("mine res: ", mine_res)
            contract_info = call_rpc('getcontractinfo', [contract_addr])
            print("contract_info after deposit is: ", contract_info)
            invoke_res = call_rpc('invokecontractoffline', [
                config['MAIN_USER_ADDRESS'], contract_addr, "query_money", "",
            ])
            print("storage.money after deposit: ", invoke_res)
            self.assertTrue(len(contract_info['balances']) > 0)
            self.assertEqual(int(invoke_res['result']), contract_info['balances'][0]['amount'])

    def multi_contract_balance_change(self):
        print("multi_contract_balance_change")
        # TODO

    def withdraw_from_contract(self, mine=True, withdraw_to_addr='18reta1dM4EkvGwWGjztSu6T48YLYPvWd'):
        print("withdraw_from_contract")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        account_balance_before_withdraw = call_rpc('listaccounts', [])[""]
        utxo = get_utxo()
        withdraw_amount = 0.3
        call_contract_script = CScript(
            [config['CONTRACT_VERSION'], str(int(withdraw_amount * config['PRECISION'])).encode("utf8"),
             "withdraw".encode("utf8"),
             contract_addr.encode("utf8"),
             config['MAIN_USER_ADDRESS'].encode('utf8'),
             5000, 40, OP_CALL])
        call_contract_script_hex = call_contract_script.hex()
        spend_contract_script = CScript([
            int(withdraw_amount * config['PRECISION']), contract_addr.encode('utf8'), OP_SPEND
        ])
        spend_contract_script_hex = spend_contract_script.hex()
        fee = 0.01
        vouts = {
            config['MAIN_USER_ADDRESS']: "%.6f" % (utxo['amount'] - fee),
            'contract': call_contract_script_hex,
            'spend_contract': [spend_contract_script_hex],
        }
        if withdraw_to_addr != config['MAIN_USER_ADDRESS']:
            vouts[withdraw_to_addr] = withdraw_amount
        else:
            vouts[config['MAIN_USER_ADDRESS']] = "%.6f" % (utxo['amount'] - fee + withdraw_amount)
        call_contract_raw_tx = call_rpc('createrawtransaction', [
            [
                {
                    'txid': utxo['txid'],
                    'vout': utxo['vout'],
                },
            ],
            vouts,
        ])
        signed_call_contract_raw_tx_res = call_rpc('signrawtransaction', [
            call_contract_raw_tx,
            [
                {
                    'txid': utxo['txid'],
                    'vout': utxo['vout'],
                    'scriptPubKey': utxo['scriptPubKey'],
                },
            ],
        ])
        self.assertEqual(signed_call_contract_raw_tx_res.get('complete', None), True)
        signed_call_contract_raw_tx = signed_call_contract_raw_tx_res.get('hex')
        print(signed_call_contract_raw_tx)
        res = call_rpc('sendrawtransaction', [signed_call_contract_raw_tx])
        print("txid: ", res)
        if mine:
            mine_res = call_rpc('generatetoaddress', [
                1, config['MAIN_USER_ADDRESS'], 1000000,
            ])
            print("mine res: ", mine_res)
            contract_info = call_rpc('getcontractinfo', [contract_addr])
            print("contract_info after withdraw is: ", contract_info)
            invoke_res = call_rpc('invokecontractoffline', [
                config['MAIN_USER_ADDRESS'], contract_addr, "query_money", "",
            ])
            print("storage.money after withdraw: ", invoke_res)
            account_balance_after_withdraw = call_rpc('listaccounts', [])[""]
            print("account change of withdraw-from-contract: %f to %f" % (
                account_balance_before_withdraw, account_balance_after_withdraw))
            mine_reward = 50
            self.assertEqual("%.6f" % (account_balance_before_withdraw + mine_reward - fee,),
                             "%.6f" % account_balance_after_withdraw)

    def test_upgrade_contract(self):
        print("test_upgrade_contract")
        contract_addr = self.test_create_contract()
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        contract_name = "contract_name_%d" % random.randint(1, 99999999)
        upgrade_contract(contract_addr, contract_name, "this is contract desc", config['MAIN_USER_ADDRESS'])
        generate_block()

    def test_many_contract_invokes_in_one_block(self):
        print("test_many_contract_invokes_in_one_block")
        contract_addr = created_contract_addr
        contract = call_rpc('getsimplecontractinfo', [contract_addr])
        n1 = 10
        n2 = 10
        # if contract balance not enough to withdraw, need to deposit some to it before test
        if len(contract['balances']) < 1 or contract['balances'][0]['amount'] < (n2 * 0.3):
            self.test_deposit_to_contract_testing()
        account_balance_before_withdraw = call_rpc('listaccounts', [])[""]
        fee = 0.01
        for i in range(n1):
            self.deposit_to_contract(False)
        for i in range(n2):
            self.withdraw_from_contract(False, config['MAIN_USER_ADDRESS'])
        mine_res = call_rpc('generatetoaddress', [
            1, config['MAIN_USER_ADDRESS'], 1000000,
        ])
        print("mine res: ", mine_res)
        contract_info = call_rpc('getcontractinfo', [contract_addr])
        print("contract_info after withdraw is: ", contract_info)
        invoke_res = call_rpc('invokecontractoffline', [
            config['MAIN_USER_ADDRESS'], contract_addr, "query_money", "",
        ])
        print("storage.money after many deposits and withdraws: ", invoke_res)
        account_balance_after_withdraw = call_rpc('listaccounts', [])[""]
        print("account change of withdraw-from-contract: %f to %f" % (
            account_balance_before_withdraw, account_balance_after_withdraw))
        mine_reward = 50
        self.assertEqual(
            "%.6f" % (account_balance_before_withdraw + mine_reward - fee * (n1 * 2 + n2) - 0.3 * n1 + 0.3 * n2,),
            "%.6f" % account_balance_after_withdraw)
        print("withdrawed amount is %.6f" % (0.3 * n2))

    def test_gas_not_enough(self):
        print("test_gas_not_enough")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        try:
            invoke_contract_api(config['MAIN_USER_ADDRESS'], contract_addr, "large", "abc")
            self.assertTrue(False)
        except Exception as e:
            print(e)

    def test_global_apis(self):
        print("test_global_apis")
        contract_addr = created_contract_addr
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        utxo = get_utxo()
        call_contract_script = CScript(
            [config['CONTRACT_VERSION'], "abc".encode('utf8'), "test_apis".encode('utf8'), contract_addr.encode("utf8"),
             config['MAIN_USER_ADDRESS'].encode('utf8'),
             5000, 40, OP_CALL])
        call_contract_script_hex = call_contract_script.hex()
        call_contract_raw_tx = call_rpc('createrawtransaction', [
            [
                {
                    'txid': utxo['txid'],
                    'vout': utxo['vout'],
                },
            ],
            {
                config['MAIN_USER_ADDRESS']: '%.6f' % (utxo['amount'] - 0.01),
                'contract': call_contract_script_hex,
            },
        ])
        signed_call_contract_raw_tx_res = call_rpc('signrawtransaction', [
            call_contract_raw_tx,
            [
                {
                    'txid': utxo['txid'],
                    'vout': utxo['vout'],
                    'scriptPubKey': utxo['scriptPubKey'],
                },
            ],
        ])
        self.assertEqual(signed_call_contract_raw_tx_res.get('complete', None), True)
        signed_call_contract_raw_tx = signed_call_contract_raw_tx_res.get('hex')
        print(signed_call_contract_raw_tx)
        call_rpc('sendrawtransaction', [signed_call_contract_raw_tx])
        mine_res = call_rpc('generatetoaddress', [
            1, config['MAIN_USER_ADDRESS'], 1000000,
        ])
        print("mine res: ", mine_res)

    def test_token_contract(self):
        print("test_token_contract")
        admin_addr = config['MAIN_USER_ADDRESS']

        for i in range(10):
            generate_block(other_addr)

        # create token contract
        utxo = get_utxo()
        bytecode_hex = read_contract_bytecode_hex("./token.gpc")
        register_contract_script = CScript(
            [config['CONTRACT_VERSION'], bytes().fromhex(bytecode_hex), config['MAIN_USER_ADDRESS'].encode('utf8'),
             5000, 40, OP_CREATE])
        create_contract_script = register_contract_script.hex()
        print("create_contract_script size %d" % len(create_contract_script))
        create_contract_raw_tx = call_rpc('createrawtransaction', [
            [
                {
                    'txid': utxo['txid'],
                    'vout': utxo['vout'],
                },
            ],
            {
                config['MAIN_USER_ADDRESS']: '%.6f' % (utxo['amount'] - 0.01),
                'contract': create_contract_script,
            },
        ])
        signed_create_contract_raw_tx_res = call_rpc('signrawtransaction', [
            create_contract_raw_tx,
            [
                {
                    'txid': utxo['txid'],
                    'vout': utxo['vout'],
                    'scriptPubKey': utxo['scriptPubKey'],
                },
            ],
        ])
        self.assertEqual(signed_create_contract_raw_tx_res.get('complete', None), True)
        signed_create_contract_raw_tx = signed_create_contract_raw_tx_res.get('hex')
        print(signed_create_contract_raw_tx)
        call_rpc('sendrawtransaction', [signed_create_contract_raw_tx])
        generate_block()
        contract_addr = call_rpc('getcreatecontractaddress', [
            signed_create_contract_raw_tx
        ])['address']
        print("new contract address: %s" % contract_addr)
        contract = call_rpc('getcontractinfo', [contract_addr])
        print("contract info: ", contract)
        print("create contract of token tests passed")

        # init config of token contract
        invoke_contract_api(admin_addr, contract_addr, "init_token", "test,TEST,1000000,100")
        generate_block()
        state = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "state", " ",
        ])['result']
        self.assertEqual(state, "COMMON")
        token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % config['MAIN_USER_ADDRESS'],
        ])['result']
        self.assertEqual(int(token_balance), 1000000)
        print("init config of token tests passed")

        # transfer
        invoke_contract_api(admin_addr, contract_addr, "transfer", "%s,%d" % (other_addr, 10000))
        generate_block()
        token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % admin_addr,
        ])['result']
        self.assertEqual(int(token_balance), 1000000 - 10000)
        other_token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % other_addr,
        ])['result']
        self.assertEqual(int(other_token_balance), 10000)
        print("transfer of token tests passed")

        # approve balance
        invoke_contract_api(admin_addr, contract_addr, "approve", "%s,%d" % (other_addr, 20000))
        generate_block()
        token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % admin_addr,
        ])['result']
        self.assertEqual(int(token_balance), 1000000 - 10000)
        other_token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % other_addr,
        ])['result']
        self.assertEqual(int(other_token_balance), 10000)
        all_approved_token_from_admin = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "allApprovedFromUser", "%s" % admin_addr,
        ])['result']
        print("all_approved_token_from_admin: ", all_approved_token_from_admin)
        other_approved_token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "approvedBalanceFrom", "%s,%s" % (other_addr, admin_addr),
        ])['result']
        self.assertEqual(int(other_approved_token_balance), 20000)
        print("approve of token tests passed")

        # transferFrom
        invoke_contract_api(other_addr, contract_addr, "transferFrom", "%s,%s,%d" % (admin_addr, other_addr, 500))
        generate_block()
        token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % admin_addr,
        ])['result']
        self.assertEqual(int(token_balance), 1000000 - 10000 - 500)
        other_token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % other_addr,
        ])['result']
        self.assertEqual(int(other_token_balance), 10000 + 500)
        other_approved_token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "approvedBalanceFrom", "%s,%s" % (other_addr, admin_addr),
        ])['result']
        print("other_approved_token_balance after transferFrom is ", other_approved_token_balance)
        self.assertEqual(int(other_approved_token_balance), 20000 - 500)
        print("transfer of token tests passed")

        # lock balance
        invoke_contract_api(admin_addr, contract_addr, "openAllowLock", " ")
        generate_block()
        cur_blockcount = call_rpc('getblockcount', [])
        locked_amount = 300
        unlock_blocknum = cur_blockcount + 2
        invoke_contract_api(admin_addr, contract_addr, "lock", "%d,%d" % (locked_amount, unlock_blocknum))
        generate_block()
        token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % admin_addr,
        ])['result']
        self.assertEqual(int(token_balance), 1000000 - 10000 - 500 - locked_amount)
        locked_balance = \
        call_rpc('invokecontractoffline', [admin_addr, contract_addr, "lockedBalanceOf", "%s" % admin_addr])['result']
        self.assertEqual(locked_balance, "%s,%d" % (locked_amount, unlock_blocknum))
        generate_block()
        invoke_contract_api(admin_addr, contract_addr, "unlock", " ")
        generate_block()
        token_balance = call_rpc('invokecontractoffline', [
            admin_addr, contract_addr, "balanceOf", "%s" % admin_addr,
        ])['result']
        self.assertEqual(int(token_balance), 1000000 - 10000 - 500)
        locked_balance = \
        call_rpc('invokecontractoffline', [admin_addr, contract_addr, "lockedBalanceOf", "%s" % admin_addr])['result']
        self.assertEqual(locked_balance, "0,0")
        print("lock of token tests passed")

    def test_price_feeder_contract(self):
        print("test_price_feeder_contract")
        caller_addr = config['MAIN_USER_ADDRESS']
        contract = None
        try:
            contract = call_rpc("getsimplecontractinfo", ["price_feeder"])
        except Exception as e:
            print(e)
            contract_addr = create_new_contract("./price_feeder.gpc")
            generate_block()
            upgrade_contract(contract_addr, "price_feeder", "price feeder contract desc", caller_addr)
            generate_block()
            contract = call_rpc("getsimplecontractinfo", ["price_feeder"])
        contract_addr = contract['id']
        print(contract_addr)
        print(contract)
        owner_addr = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "owner", " ",
        ])['result']
        self.assertEqual(owner_addr, caller_addr)
        to_feed_tokens = json.loads(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "to_feed_tokens", " ",
        ])['result'])
        if len(to_feed_tokens) < 1:
            res = invoke_contract_api(caller_addr, contract_addr, "add_feed_token", "%s,%d" % ("CNY", 10 ** 8))
            generate_block(caller_addr)
            to_feed_tokens = json.loads(call_rpc('invokecontractoffline', [
                caller_addr, contract_addr, "to_feed_tokens", " ",
            ])['result'])
        print("to feed tokens: ", to_feed_tokens)
        feeders = json.loads(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "feeders", " ",
        ])['result'])
        print("feeders: ", feeders)
        if len(feeders) == 1 and feeders[0] == caller_addr:
            invoke_contract_api(caller_addr, contract_addr, "add_feeder", "%s" % other_addr)
            generate_block(caller_addr)
            feeders_after_add = json.loads(call_rpc('invokecontractoffline', [
                caller_addr, contract_addr, "feeders", " ",
            ])['result'])
            print("feeders_after_add: ", feeders_after_add)
            self.assertEqual(len(feeders_after_add), 2)
            invoke_contract_api(caller_addr, contract_addr, "remove_feeder", "%s" % other_addr)
            generate_block(caller_addr)
            feeders_after_removed = json.loads(call_rpc('invokecontractoffline', [
                caller_addr, contract_addr, "feeders", " ",
            ])['result'])
            print("feeders_after_removed: ", feeders_after_removed)
            self.assertEqual(len(feeders_after_removed), 1)
        elif len(feeders) > 1:
            invoke_contract_api(caller_addr, contract_addr, "remove_feeder", "%s" % other_addr)
            generate_block(caller_addr)
            feeders_after_removed = json.loads(call_rpc('invokecontractoffline', [
                caller_addr, contract_addr, "feeders", " ",
            ])['result'])
            print("feeders_after_removed: ", feeders_after_removed)
        all_token_prices = json.loads(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "all_token_prices", " ",
        ])['result'])
        print("all_token_prices: ", all_token_prices)
        price_of_cny = json.loads(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "price_of_token", "CNY",
        ])['result'])
        print("price of cny: ", price_of_cny)

    def test_constant_value_token_contract(self):
        print("test_constant_value_token_contract")
        self.test_price_feeder_contract()
        caller_addr = config['MAIN_USER_ADDRESS']
        contract_addr = create_new_contract("./any_mortgage_token.gpc")
        generate_block(caller_addr)
        state = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "state", " ",
        ])['result']
        self.assertEqual(state, "NOT_INITED")
        invoke_contract_api(caller_addr, contract_addr,
                            "init_token", "%s,%d,%d,%s,%d" % ("test", 1000000, 100, "CNY", 110000))
        generate_block(caller_addr)
        state = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "state", " ",
        ])['result']
        self.assertEqual(state, "COMMON")
        deposit_to_contract(caller_addr, contract_addr, 10, "memo123")
        invoke_contract_api(caller_addr, contract_addr, "mint", "200000")
        generate_block(caller_addr)
        admin = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "admin", " ",
        ])['result']
        print("admin: ", admin)
        self.assertEqual(admin, caller_addr)
        total_supply = int(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "totalSupply", " ",
        ])['result'])
        self.assertEqual(total_supply, 1200000)
        precision = int(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "precision", " ",
        ])['result'])
        print("precision: ", precision)
        self.assertEqual(precision, 100)
        token_name = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "tokenName", " ",
        ])['result']
        print("token name: ", token_name)
        self.assertEqual(token_name, "test")
        invoke_contract_api(caller_addr, contract_addr, "destroy", "100000")
        generate_block(caller_addr)
        total_supply = int(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "totalSupply", " ",
        ])['result'])
        self.assertEqual(total_supply, 1100000)
        mortgage_rate = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "mortgageRate", " ",
        ])['result']
        print("mortgage_rate: ", mortgage_rate)
        self.assertEqual(mortgage_rate, "0.000826")
        mortgage_balance = int(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "mortgageBalance", " ",
        ])['result'])
        print("mortgage_balance before withdraw: ", mortgage_balance)
        self.assertEqual(mortgage_balance, 10 * config['PRECISION'])

        withdraw_res = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "withdraw_unused", "%d" % (5 * config['PRECISION']),
        ])
        print(withdraw_res)
        withdraw_from_infos = {}
        for change in withdraw_res['balanceChanges']:
            if change["is_contract"] and not change["is_add"]:
                withdraw_from_infos[change["address"]] = change["amount"] * 1.0 / config["PRECISION"]
        withdraw_infos = {}
        for change in withdraw_res["balanceChanges"]:
            if not change["is_contract"] and change["is_add"]:
                withdraw_infos[change["address"]] = change["amount"] * 1.0 / config["PRECISION"]
        invoke_contract_api(caller_addr, contract_addr, "withdraw_unused", "%d" % (5 * config['PRECISION']),
                            withdraw_infos, withdraw_from_infos)
        generate_block(caller_addr)
        mortgage_rate = call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "mortgageRate", " ",
        ])['result']
        print("mortgage_rate after withdraw: ", mortgage_rate)
        self.assertEqual(mortgage_rate, "0.000413")
        mortgage_balance = int(call_rpc('invokecontractoffline', [
            caller_addr, contract_addr, "mortgageBalance", " ",
        ])['result'])
        print("mortgage_balance after withdraw: ", mortgage_balance)
        self.assertEqual(mortgage_balance, 5 * config['PRECISION'])


def main():
    unittest.main()


if __name__ == '__main__':
    main()
