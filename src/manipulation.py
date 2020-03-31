import enum
import inspect
from collections import namedtuple


class ManipulateActions(enum.Enum):
    DROP = 0
    # The manipulator will deal with tagging, if needed.
    INJECT_RAW = 1
    # The switch should deal with tagging, if needed.
    HANDLE_ENCAP = 2


ManipulateArgs = namedtuple('ManipulateInfo', [
    'packet',
    # can be used if the manipulator wants to deal with tagging.
    'is_trunk_port',
    'src_vlan',
])

ManipulateRet = namedtuple('ManipulateRet', [
    'packet',
    # From ManipulateActions
    'action',
])


def default_manipulation_cb(manipulate_args: ManipulateArgs) -> ManipulateRet:
    '''
    Can be used as an example of a valid signature of manipulation callback.
    This default callback just returns the packet.
    '''
    return ManipulateRet(manipulate_args.packet, ManipulateActions.HANDLE_ENCAP)


def validate_manipulation_cb(cb):
    # TODO: Currently annotations are required in order to check
    # function's signature
    sig = inspect.signature(cb)

    if len(sig.parameters) != 1:
        return False

    param = list(sig.parameters.values())[0]

    return param.annotation == ManipulateArgs and sig.return_annotation == ManipulateRet
