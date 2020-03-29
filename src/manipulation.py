import inspect
from collections import namedtuple

ManipulateArgs = namedtuple('ManipulateInfo', [
    'packet',
    # can be used if the manipulator wants to deal with tagging.
    'is_trunk_port',
    'src_vlan',
])

ManipulateRet = namedtuple('ManipulateRet', [
    'packet',
    # In case you want to deal with tagging (add dot1q layer),
    # this should be set to True.
    'should_inject_raw',
])


def default_manipulation_cb(manipulate_args: ManipulateArgs) -> ManipulateRet:
    '''
    Can be used as an example of a valid signature of manipulation callback.
    This default callback just returns the packet.
    '''
    return ManipulateRet(manipulate_args.packet, False)


def validate_manipulation_cb(cb):
    # TODO: Currently annotations are required in order to check
    # function's signature
    sig = inspect.signature(cb)

    if len(sig.parameters) != 1:
        return False

    param = list(sig.parameters.values())[0]

    return param.annotation == ManipulateArgs and sig.return_annotation == ManipulateRet
