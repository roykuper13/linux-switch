import inspect
from collections import namedtuple


ManipulateArgs = namedtuple('ManipulateInfo', [
    'packet',
    # can be used if the manipulator wants to deal with tagging.
    'is_trunk_port',
    'src_vlan',
])


def validate_manipulation_cb(cb):
    # TODO: Currently annotations are required in order to check
    # function's signature
    sig = inspect.signature(cb)

    if len(sig.parameters) != 1:
        return False

    param = list(sig.parameters.values())[0]

    return param.annotation == ManipulateArgs
