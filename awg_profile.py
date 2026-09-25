"""AWG wire-profile settings, pinned to AmneziaVPN 5.0.3.0 defaults.

Protocol and package versions differ. Legacy bundles without AWG_PROTOCOL are
AWG 2.0; never upgrade them implicitly. HeaderProtectionKey is secret.
"""
import base64
import json
import secrets

V3_FIELDS = (
    'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime',
    'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
    'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies',
)
MATCH_FIELDS = ('S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4') + V3_FIELDS
EXPORT_FIELDS = MATCH_FIELDS + ('I1', 'I2', 'I3', 'I4', 'I5', 'Jc', 'Jmin', 'Jmax')


def new_profile():
    # client/core/utils/constants/protocolConstants.h at tag 5.0.3.0.
    return dict(new_profile_template(), Jc=str(4 + secrets.randbelow(3)),
                HeaderProtectionKey=base64.b64encode(secrets.token_bytes(32)).decode())


def version(state):
    value = state.get('AWG_PROTOCOL', '2')
    if value not in {'2', '3.1'}:
        raise ValueError('unsupported saved AWG protocol')
    return value


def parameters(state, legacy):
    if version(state) == '2':
        return dict(legacy)
    value = json.loads(state['AWG_PARAMETERS'])
    expected = new_profile_keys()
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('incomplete AWG 3.1 profile')
    if any(not isinstance(v, str) or '\n' in v or '\r' in v for v in value.values()):
        raise ValueError('invalid AWG profile value')
    try:
        key = base64.b64decode(value['HeaderProtectionKey'], validate=True)
    except ValueError:
        raise ValueError('invalid header protection key') from None
    if len(key) != 32 or base64.b64encode(key).decode() != value['HeaderProtectionKey']:
        raise ValueError('invalid header protection key')
    # This implementation supports one verified preset, not arbitrary tuning.
    fixed = dict(new_profile_template())
    if any(value[k] != v for k, v in fixed.items()):
        raise ValueError('unsupported AWG 3.1 preset; no settings changed')
    if value['Jc'] not in {'4', '5', '6'}:
        raise ValueError('invalid AWG junk count')
    return value


def new_profile_template():
    return {
        'Jmin': '10', 'Jmax': '50', 'S1': '12', 'S2': '12', 'S3': '12', 'S4': '12',
        'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4',
        'I1': '<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>',
        'ContentPaddingAddition': '10-100', 'RekeyAfterTime': '100-120',
        'RekeyTimeout': '3-7', 'RejectAfterTime': '150-180',
        'KeepaliveTimeout': '5-15', 'MaxHandshakeAttempts': '15-20',
        'RandomTrailers': 'on', 'DisableCookies': 'off',
    }


def new_profile_keys():
    return set(new_profile_template()) | {'Jc', 'HeaderProtectionKey'}


def keepalive(state):
    return '25-35' if version(state) == '3.1' else '25'
