# -*- coding: utf-8 -*-
from persistent import Persistent

class Gadget(Persistent):
    """
    Describes a ROP gadget
    """

    #: Address of the first instruction of the gadget
    address = 0

    #: List of disassembled instruction mnemonics
    #:
    #: Examples:
    #:      ['pop eax', 'ret']
    insns = []

    #: OrderedDict of register to:
    #:
    #: - Offset from the top of the frame at which it's set
    #: - Name of the register which it is set from
    #:
    #: Order is determined by the order of instructions.
    #:
    #: Examples:
    #:
    #: ret => {}
    #: pop eax; ret => {'eax': 0}
    #: pop ebx; pop eax; ret => {'ebx': 0, 'eax': 4}
    #: add esp, 0x10; pop ebx; ret => {'ebx': 16}
    #: mov eax, ebx; ret => {'eax': 'ebx'}
    regs = {}

    #: The total amount that the stack pointer is modified by
    #:
    #: Examples:
    #:      ret ==> 4
    #:      add esp, 0x10; ret ==> 0x14
    move = 0

    #: Gadget raw bytes
    #: 
    #: Example:
    #:      'mov eax, ebx ; ret 4' ==> '\x89\xd8\xc2\x04\x00'
    bytes = ""

    def __init__(self, address, insns, regs, move, bytes):
        self.address = address
        self.insns   = insns
        self.regs    = regs
        self.move    = move

        #Gadget raw bytes 
        self.bytes   = bytes

    __indices = ['address', 'details']

    def __repr__(self):
        return "%s(%#x, %r, %r, %#x)" % (self.__class__.__name__,
                                         self.address,
                                         self.insns,
                                         self.regs,
                                         self.move)

    def __getitem__(self, key):
        # Backward compatibility
        if isinstance(key, int):
            key = self.__indices[key]
        return getattr(self, key)

    def __setitem__(self, key, value):
        # Backward compatibility
        if isinstance(key, int):
            key = self.__indices[key]
        return setattr(self, key, value)

    def __eq__(self, other):
        """
        Return self == other
        """
        if type(other) is type(self):
            same_address    = self.address  == other.address
            same_move       = self.move     == other.move
            same_insns      = self.insns    == other.insns

            return same_address and same_insns and same_move
        else:
            return False

    def __hash__(self):
        return hash((self.address, "; ".join(self.insns), self.move))

class Mem(Persistent):
    """
    Describes a Mem postion for gadget.

    Distinguish it from a Immediate Num.
    """

    #: Example:
    #:      pop eax; ret
    #:          {"eax": Mem("esp", 0, 32)}, not {"eax": 0}
    #:      move eax, 0x1234; ret
    #:          {"eax": 1234}

    __slots__ = ['reg', 'offset', 'size']

    def __init__(self, reg, offset=0, size=32):
        self.reg = reg
        self.offset = offset
        self.size = size

    def __str__(self):
        return "M%d(%s, #%x)" % (self.size, self.reg, self.offset)

    def __repr__(self):
        return "M%d(%s, #%x)" % (self.size, self.reg, self.offset)

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        return setattr(self, key, value)

    def __eq__(self, other):
        """Return self == other
        """
        if type(other) is type(self):
            same_reg    = self.reg      == other.reg
            same_offset = self.offset   == other.offset
            same_size   = self.size     == other.size

            return same_reg and same_offset and same_size
        else:
            return False

    def __hash__(self):
        return hash((self.reg, self.offset, self.size))
