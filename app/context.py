# app/context.py
MOCK_INTEL = {
    '203.0.113.50': {
        'reputation': 'malicious',
        'tags': ['credential-stuffing'],
        'note': 'Seen in credential-stuffing feeds. Treat any successful login from this IP as suspect.',
    },
    '198.51.100.7': {
        'reputation': 'clean',
        'tags': [],
        'note': 'Internal vulnerability scanner.',
    },
}
MOCK_ASSETS = {
    'fin-ws-014': {
        'criticality': 'high',
        'owner': 'finance',
        'note': 'Finance workstation with access to payment systems.',
    },
    'dev-ws-221': {
        'criticality': 'low',
        'owner': 'engineering',
        'note': 'Developer workstation with no production access.',
    },
}
UNKNOWN_IP = {'reputation': 'unknown', 'tags': [], 'note': 'No intel on this IP.'}
UNKNOWN_ASSET = {'criticality': 'unknown', 'owner': 'unknown', 'note': 'Asset not in inventory.'}
