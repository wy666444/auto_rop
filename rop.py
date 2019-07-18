r"""
Return Oriented Programming

Manual ROP
-------------------

The ROP tool can be used to build stacks pretty trivially.
Let's create a fake binary which has some symbols which might
have been useful.

    >>> context.clear(arch='i386')
    >>> binary = ELF.from_assembly('add esp, 0x10; ret')
    >>> binary.symbols = {'read': 0xdeadbeef, 'write': 0xdecafbad, 'exit': 0xfeedface}

Creating a ROP object which looks up symbols in the binary is
pretty straightforward.

    >>> rop = ROP(binary)

With the ROP object, you can manually add stack frames.

    >>> rop.raw(0)
    >>> rop.raw(unpack('abcd'))
    >>> rop.raw(2)

Inspecting the ROP stack is easy, and laid out in an easy-to-read
manner.

    >>> print rop.dump()
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2

The ROP module is also aware of how to make function calls with
standard Linux ABIs.

    >>> rop.call('read', [4,5,6])
    >>> print rop.dump()
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2
    0x000c:       0xdeadbeef read(4, 5, 6)
    0x0010:           'eaaa' <pad>
    0x0014:              0x4 arg0
    0x0018:              0x5 arg1
    0x001c:              0x6 arg2

You can also use a shorthand to invoke calls.
The stack is automatically adjusted for the next frame

    >>> rop.write(7,8,9)
    >>> rop.exit()
    >>> print rop.dump()
    0x0000:              0x0
    0x0004:       0x64636261
    0x0008:              0x2
    0x000c:       0xdeadbeef read(4, 5, 6)
    0x0010:       0x10000000 <adjust: add esp, 0x10; ret>
    0x0014:              0x4 arg0
    0x0018:              0x5 arg1
    0x001c:              0x6 arg2
    0x0020:           'iaaa' <pad>
    0x0024:       0xdecafbad write(7, 8, 9)
    0x0028:       0x10000000 <adjust: add esp, 0x10; ret>
    0x002c:              0x7 arg0
    0x0030:              0x8 arg1
    0x0034:              0x9 arg2
    0x0038:           'oaaa' <pad>
    0x003c:       0xfeedface exit()

ROP Example
-------------------

Let's assume we have a trivial binary that just reads some data
onto the stack, and returns.

    >>> context.clear(arch='i386')
    >>> c = constants
    >>> assembly =  'read:'      + shellcraft.read(c.STDIN_FILENO, 'esp', 1024)
    >>> assembly += 'ret\n'

Let's provide some simple gadgets:

    >>> assembly += 'add_esp: add esp, 0x10; ret\n'

And perhaps a nice "write" function.

    >>> assembly += 'write: enter 0,0\n'
    >>> assembly += '    mov ebx, [ebp+4+4]\n'
    >>> assembly += '    mov ecx, [ebp+4+8]\n'
    >>> assembly += '    mov edx, [ebp+4+12]\n'
    >>> assembly += shellcraft.write('ebx', 'ecx', 'edx')
    >>> assembly += '    leave\n'
    >>> assembly += '    ret\n'
    >>> assembly += 'flag: .asciz "The flag"\n'

And a way to exit cleanly.

    >>> assembly += 'exit: ' + shellcraft.exit(0)
    >>> binary   = ELF.from_assembly(assembly)

Finally, let's build our ROP stack

    >>> rop = ROP(binary)
    >>> rop.write(c.STDOUT_FILENO, binary.symbols['flag'], 8)
    >>> rop.exit()
    >>> print rop.dump()
    0x0000:       0x10000012 write(STDOUT_FILENO, 268435494, 8)
    0x0004:       0x1000000e <adjust: add esp, 0x10; ret>
    0x0008:              0x1 arg0
    0x000c:       0x10000026 flag
    0x0010:              0x8 arg2
    0x0014:           'faaa' <pad>
    0x0018:       0x1000002f exit()

The raw data from the ROP stack is available via `str`.

    >>> raw_rop = str(rop)
    >>> print enhex(raw_rop)
    120000100e000010010000002600001008000000666161612f000010

Let's try it out!

    >>> p = process(binary.path)
    >>> p.send(raw_rop)
    >>> print p.recvall(timeout=5)
    The flag

ROP + Sigreturn
-----------------------

In some cases, control of the desired register is not available.
However, if you have control of the stack, EAX, and can find a
`int 0x80` gadget, you can use sigreturn.

Even better, this happens automagically.

Our example binary will read some data onto the stack, and
not do anything else interesting.

    >>> context.clear(arch='i386')
    >>> c = constants
    >>> assembly =  'read:'      + shellcraft.read(c.STDIN_FILENO, 'esp', 1024)
    >>> assembly += 'ret\n'
    >>> assembly += 'pop eax; ret\n'
    >>> assembly += 'int 0x80\n'
    >>> assembly += 'binsh: .asciz "/bin/sh"'
    >>> binary    = ELF.from_assembly(assembly)

Let's create a ROP object and invoke the call.

    >>> context.kernel = 'amd64'
    >>> rop   = ROP(binary)
    >>> binsh = binary.symbols['binsh']
    >>> rop.execve(binsh, 0, 0)

That's all there is to it.

    >>> print rop.dump()
    0x0000:       0x1000000e pop eax; ret
    0x0004:             0x77
    0x0008:       0x1000000b int 0x80
    0x000c:              0x0 gs
    0x0010:              0x0 fs
    0x0014:              0x0 es
    0x0018:              0x0 ds
    0x001c:              0x0 edi
    0x0020:              0x0 esi
    0x0024:              0x0 ebp
    0x0028:              0x0 esp
    0x002c:       0x10000012 ebx = binsh
    0x0030:              0x0 edx
    0x0034:              0x0 ecx
    0x0038:              0xb eax
    0x003c:              0x0 trapno
    0x0040:              0x0 err
    0x0044:       0x1000000b int 0x80
    0x0048:             0x23 cs
    0x004c:              0x0 eflags
    0x0050:              0x0 esp_at_signal
    0x0054:             0x2b ss
    0x0058:              0x0 fpstate

Let's try it out!

    >>> p = process(binary.path)
    >>> p.send(str(rop))
    >>> time.sleep(1)
    >>> p.sendline('echo hello; exit')
    >>> p.recvline()
    'hello\n'
"""
import collections
import hashlib
import os
import re
import sys
import tempfile
import random
import networkx

from multiprocessing import Pool, cpu_count
from itertools  import repeat
from operator   import itemgetter
from copy       import deepcopy

from ..         import abi
from ..         import constants

from ..context  import context, LocalContext
from ..elf      import ELF
from ..log      import getLogger
from ..util     import cyclic
from ..util     import lists
from ..util     import packing
from .          import srop
from .call      import Call, StackAdjustment, AppendedArgument, CurrentStackPointer, NextGadgetAddress
from .gadgets   import Gadget, Mem
from .gadgetfinder  import GadgetFinder, GadgetSolver
from ..util.packing import *

log = getLogger(__name__)
__all__ = ['ROP']


class Padding(object):
    """
    Placeholder for exactly one pointer-width of padding.
    """

class DescriptiveStack(list):
    """
    List of resolved ROP gadgets that correspond to the ROP calls that
    the user has specified.  Also includes
    """

    #: Base address
    address = 0

    #: Dictionary of ``{address: [list of descriptions]}``
    descriptions = {}

    def __init__(self, address):
        self.descriptions = collections.defaultdict(lambda: [])
        self.address      = address or 0

    @property
    def next(self):
        return self.address + len(self) * context.bytes

    def describe(self, text, address = None):
        if address is None:
            address = self.next
        self.descriptions[address] = text

    def dump(self):
        rv = []
        for i, data in enumerate(self):
            addr = self.address + i * context.bytes
            off = None
            line = '0x%04x:' % addr
            if isinstance(data, str):
                line += ' %16r' % data
            elif isinstance(data, (int,long)):
                line += ' %#16x' % data
                if self.address != 0 and self.address < data < self.next:
                    off = data - addr
            else:
                log.error("Don't know how to dump %r" % data)
            desc = self.descriptions.get(addr, '')
            if desc:
                line += ' %s' % desc
            if off is not None:
                line += ' (+%#x)' % off
            rv.append(line)

        return '\n'.join(rv)


class ROP(object):
    r"""Class which simplifies the generation of ROP-chains.

    Example:

    .. code-block:: python

       elf = ELF('ropasaurusrex')
       rop = ROP(elf)
       rop.read(0, elf.bss(0x80))
       rop.dump()
       # ['0x0000:        0x80482fc (read)',
       #  '0x0004:       0xdeadbeef',
       #  '0x0008:              0x0',
       #  '0x000c:        0x80496a8']
       str(rop)
       # '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'

    >>> context.clear(arch = "i386", kernel = 'amd64')
    >>> assembly = 'int 0x80; ret; add esp, 0x10; ret; pop eax; ret'
    >>> e = ELF.from_assembly(assembly)
    >>> e.symbols['funcname'] = e.address + 0x1234
    >>> r = ROP(e)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x0000:       0x10001234 funcname(1, 2)
    0x0004:       0x10000003 <adjust: add esp, 0x10; ret>
    0x0008:              0x1 arg0
    0x000c:              0x2 arg1
    0x0010:           'eaaa' <pad>
    0x0014:           'faaa' <pad>
    0x0018:       0x10001234 funcname(3)
    0x001c:       0x10000007 <adjust: pop eax; ret>
    0x0020:              0x3 arg0
    0x0024:       0x10000007 pop eax; ret
    0x0028:             0x77
    0x002c:       0x10000000 int 0x80
    0x0030:              0x0 gs
    0x0034:              0x0 fs
    0x0038:              0x0 es
    0x003c:              0x0 ds
    0x0040:              0x0 edi
    0x0044:              0x0 esi
    0x0048:              0x0 ebp
    0x004c:              0x0 esp
    0x0050:              0x4 ebx
    0x0054:              0x6 edx
    0x0058:              0x5 ecx
    0x005c:              0xb eax
    0x0060:              0x0 trapno
    0x0064:              0x0 err
    0x0068:       0x10000000 int 0x80
    0x006c:             0x23 cs
    0x0070:              0x0 eflags
    0x0074:              0x0 esp_at_signal
    0x0078:             0x2b ss
    0x007c:              0x0 fpstate

    >>> assembly += "; pop ebx; ret"
    >>> e = ELF.from_assembly(assembly)
    >>> e.symbols['funcname'] = e.address + 0x1234
    >>> r = ROP(e, 0x8048000)
    >>> r.funcname(1, 2)
    >>> r.funcname(3)
    >>> r.execve(4, 5, 6)
    >>> print r.dump()
    0x8048000:       0x10001234 funcname(1, 2)
    0x8048004:       0x10000003 <adjust: add esp, 0x10; ret>
    0x8048008:              0x1 arg0
    0x804800c:              0x2 arg1
    0x8048010:           'eaaa' <pad>
    0x8048014:           'faaa' <pad>
    0x8048018:       0x10001234 funcname(3)
    0x804801c:       0x10000007 <adjust: pop eax; ret>
    0x8048020:              0x3 arg0
    0x8048024:       0x10000007 pop eax; ret
    0x8048028:             0x77
    0x804802c:       0x10000000 int 0x80
    0x8048030:              0x0 gs
    0x8048034:              0x0 fs
    0x8048038:              0x0 es
    0x804803c:              0x0 ds
    0x8048040:              0x0 edi
    0x8048044:              0x0 esi
    0x8048048:              0x0 ebp
    0x804804c:        0x8048080 esp
    0x8048050:              0x4 ebx
    0x8048054:              0x6 edx
    0x8048058:              0x5 ecx
    0x804805c:              0xb eax
    0x8048060:              0x0 trapno
    0x8048064:              0x0 err
    0x8048068:       0x10000000 int 0x80
    0x804806c:             0x23 cs
    0x8048070:              0x0 eflags
    0x8048074:              0x0 esp_at_signal
    0x8048078:             0x2b ss
    0x804807c:              0x0 fpstate
    """
    #: List of individual ROP gadgets, ROP calls, SROP frames, etc.
    #: This is intended to be the highest-level abstraction that we can muster.
    _chain = []

    #: List of ELF files which are available for mining gadgets
    elfs = []

    #: Stack address where the first byte of the ROP chain lies, if known.
    base = 0

    #: Alignment of the ROP chain; generally the same as the pointer size
    align = 4

    #: Whether or not the ROP chain directly sets the stack pointer to a value
    #: which is not contiguous
    migrated = False

    @LocalContext
    def __init__(self, elfs, base = None, **kwargs):
        """
        Arguments:
            elfs(list): List of ``pwnlib.elf.ELF`` objects for mining
        """

        # Permit singular ROP(elf) vs ROP([elf])
        if isinstance(elfs, ELF):
            elfs = [elfs]
        elif isinstance(elfs, (str, unicode)):
            elfs = [ELF(elfs)]
        self.elfs = elfs
        self._chain = []
        self.base = base
        self.align = context.bits / 8
        self.migrated = False

        if elfs[0].arch != context.arch:
            log.error("Context arch should be the same as binary arch.")
        self.arch = context.arch

        #Find all gadgets
        gf = GadgetFinder(elfs, "all")
        self.gadgets = gf.load_gadgets()

        self.Verify = gf.solver

        self.initialized = False
        self.__init_arch_info()

        self.gadget_graph = self.build_graph(self.gadgets)

        self._top_sorted = networkx.topological_sort(self.gadget_graph, reverse=True)

        self.ret_to_stack_gadget = None

    @staticmethod
    @LocalContext
    def from_blob(blob, *a, **kw):
        return ROP(ELF.from_bytes(blob, *a, **kw))

    def __init_arch_info(self):
        self.CALL = { "i386"    : "call",
                      "amd64"   : "call",
                      "arm"     : "blx"}[self.arch]
        self.JUMP = { "i386"    : "jmp",
                      "amd64"   : "jmp",
                      "arm"     : "bx"}[self.arch]
        self.PC   = { "i386"    : "eip",
                      "amd64"   : "rip",
                      "arm"     : "pc"}[self.arch]
        self.RET  = { "i386"    : "ret",
                      "amd64"   : "ret",
                      "arm"     : "pop"}[self.arch]
        self.SP   = { "i386"    : "esp",
                      "amd64"   : "rsp",
                      "arm"     : "sp"}[self.arch]


    def setRegisters_print(self, condition):
        for r, gadgets in self.setRegisters(condition).items():
            print '<setting %s>' % r
            offset = 0
            for g in gadgets:
                if isinstance(g, Gadget):
                    print hex(g.address), '; '.join(g.insns)
                elif isinstance(g, int):  print hex(g)
                elif isinstance(g, Padding):
                    print self.generatePadding(offset,context.bytes)
                    offset += context.bytes

                else: print g

    def setRegisters(self, values):
        """
        Provides a sequence of ROP gadgets which will set the desired register
        values.

        Arguments:

            values(dict):
                Mapping of ``{register name: value}``.  The contents of
                ``value`` can be any object, not just an integer.

        Return Value:

            Returns a ``collections.OrderedDict`` object which is in the
            correct order of operations.

            The keys are the register names, and the values are the sequence
            of stack values necessary to set the register.

        Example:

            Example for i386:

            >>> context.clear(arch='i386')
            >>> assembly  = 'pop eax; ret;'
            >>> assembly += 'mov ebx, eax; ret;'
            >>> assembly += 'pop ecx; call eax'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> con = {'eax':1, 'ebx':2, 'ecx':3}
            >>> rop.setRegisters_print(con)
            <setting ecx>
            0x10000000 pop eax; ret
            0x10000000
            0x10000005 pop ecx; call eax
            0x3
            <setting ebx>
            0x10000000 pop eax; ret
            0x2
            0x10000002 mov ebx, eax; ret
            <setting eax>
            0x10000000 pop eax; ret
            0x1

            i386 Example - advance gadget arrangement:

            >>> context.clear(arch='i386')
            >>> assembly  = "read:" + shellcraft.read(0, 'esp', 0x1000)
            >>> assembly += 'pop eax; ret;'
            >>> assembly += 'xchg edx, ecx; jmp eax;'
            >>> assembly += 'pop ecx; ret'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> con = {'edx': unpack('_EDX')}
            >>> rop.setRegisters_print(con)
            <setting edx>
            0x10000013 pop ecx; ret
            0x5844455f
            0x1000000d pop eax; ret
            0x1000000e
            0x1000000f xchg edx, ecx; jmp eax

            i386 Exmaple - check regs from the same origin:

            >>> context.clear(arch='i386')
            >>> assembly = 'mov eax, [esp]; pop ebx; ret'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> con = {'eax': 0, 'ebx':1}
            >>> rop.setRegisters_print(con)
            <setting eax>
            0x10000000 mov eax, dword ptr [esp]; pop ebx; ret
            0x0
            <setting ebx>
            0x10000003 pop ebx; ret
            0x1

            i386 Example - handle overlapping ret address.

            >>> context.clear(arch='i386')
            >>> assembly  = 'add esp, 0x10; ret;'
            >>> assembly += 'add esp, 0xc; ret;'
            >>> assembly += 'add esp, 0x8; ret;'
            >>> assembly += 'pop eax; ret;'
            >>> assembly += 'pop ebx; call eax;'
            >>> assembly += 'mov ecx, ebx; ret;'
            >>> assembly += 'xchg edx, ecx; jmp eax;'
            >>> assembly += 'mov edi, [esp+8]; add esp, 4; ret'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> con = {'edi': 0xdeadbeef}
            >>> rop.setRegisters_print(con)
            <setting edi>
            0x10000018 mov edi, dword ptr [esp + 8]; add esp, 4; ret
            aaaa
            0x1000000c
            0xdeadbeef

            i386 Example - complicated example.

            >>> context.clear(arch='i386')
            >>> assembly  = 'pop eax; ret;'
            >>> assembly += 'pop ebx; call eax;'
            >>> assembly += 'mov ecx, ebx; ret;'
            >>> assembly += 'xchg edx, ecx; jmp eax;'
            >>> assembly += 'mov edi, edx; ret'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> con = {'eax': 1, 'ebx': 2, 'ecx': 3, 'edx': 4}
            >>> rop.setRegisters_print(con)
            <setting edx>
            0x10000000 pop eax; ret
            0x10000000
            0x10000002 pop ebx; call eax
            0x4
            0x10000005 mov ecx, ebx; ret
            0x10000008 xchg edx, ecx; jmp eax
            aaaa
            <setting ecx>
            0x10000000 pop eax; ret
            0x10000000
            0x10000002 pop ebx; call eax
            0x3
            0x10000005 mov ecx, ebx; ret
            <setting ebx>
            0x10000000 pop eax; ret
            0x10000000
            0x10000002 pop ebx; call eax
            0x2
            <setting eax>
            0x10000000 pop eax; ret
            0x1

            Example for ARM - advance gadgets arrangement:

            >>> context.clear(arch='arm')
            >>> assembly  = 'pop {r0, pc};'
            >>> assembly += 'pop {r0, r1, pc};'
            >>> assembly += 'pop {r0, r2, pc};'
            >>> assembly += 'mov r3, r2; pop {pc};'
            >>> assembly += 'mov r4, r0; blx r1'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> rop.setRegisters_print({'r4': 1})
            <setting r4>
            0x10000004 pop {r0, r1, pc}
            0x1
            0x10000010
            0x10000014 mov r4, r0; blx r1

            Arm Example 02 - migrate to $sp:

            >>> context.clear(arch='arm')
            >>> assembly  = 'pop {lr};'
            >>> assembly += 'bx lr'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> rop.setRegisters_print({'pc' : 1})
            <setting pc>
            0x10000000 pop {lr}; bx lr
            0x1

            Arm Example 03 - migrate to $sp:

            >>> context.clear(arch='arm')
            >>> assembly = 'pop {pc}'
            >>> rop = ROP(ELF.from_assembly(assembly))
            >>> rop.setRegisters_print({'pc' : 0xdeadbeef})
            <setting pc>
            0x10000000 pop {pc}
            0xdeadbeef
        """

        out = []

        # Such as: {path_md5_hash: path}
        ropgadgets = {}

        # Such as: {path_md5_hash: set(regs)}
        gadget_list = {}

        # Convert the values into dict format.
        if isinstance(values, list):
            values = dict(values)

        def md5_path(path):
            out = []
            for gadget in path:
                out.append("; ".join(gadget.insns))

            return hashlib.md5("|".join(out)).hexdigest()

        def record(gadget_paths, reg):
            for path in gadget_paths:
                path_hash= md5_path(path)

                ropgadgets[path_hash] = path

                if path_hash not in gadget_list.keys():
                    gadget_list[path_hash] = set()
                gadget_list[path_hash].add(reg)


        for reg, value in values.items():

            gadget_paths = self.search_path("sp", [reg])

            if not gadget_paths:
                log.error("Gadget to reg %s not found!" % reg)

            # Combine the same gadgets together.
            # pop rdi; pop rsi; ret
            # set rdi = xxx; set rsi = yyy
            # This gadget will meet these two conditions
            # No need using two gadgets respectively.
            record(gadget_paths, reg)


        # Combine the same gadgets together.
        # See the comments above.
        # Sort the dict using two args:
        #   arg1: number of registers, reverse order.
        #   arg2: length of path's instructions
        def re_order(gadget_list, remain_regs=set()):
            result = collections.OrderedDict()
            temp = {}
            for path_hash, regs in gadget_list.items():
                if remain_regs:
                    number = len(remain_regs & regs)
                else:
                    number = len(regs)
                temp[path_hash] = number

            return collections.OrderedDict(sorted(gadget_list.items(), key=lambda t:(-temp[t[0]],
                          len("; ".join([ "; ".join(i.insns) for i in ropgadgets[t[0]]])))))

        gadget_list = re_order(gadget_list)

        reg_without_ip = values.keys()
        remain_regs = set(reg_without_ip)
        used_regs = set()
        additional_conditions = {}

        # Try to match a path based on remain registers.
        # If matched, verify this path, and caculate the remain registers.
        # If not, continue to match, until there are no paths in gadget_list
        while True:
            if gadget_list:
                path_hash, regs = gadget_list.popitem(0)
            else:
                break

            if not remain_regs:
                break

            modified_regs = remain_regs & regs
            if modified_regs:
                path = ropgadgets[path_hash]

                # If two or more regs source from same origin,
                # Nop and push back this gadget path
                if self.check_same_origin(path, modified_regs):
                    gadget_list[path_hash] = regs
                    continue

                result = self.handle_non_ret_branch(path)
                if not result:
                    continue

                path, return_to_stack_gadget, conditions, additional = result
                additional_conditions.update(additional)

                # If conditions'key in Gadget's registers.
                # Handle this conflict.
                for conflict_key in conditions.keys():
                    if conflict_key in modified_regs:
                        modified_regs.remove(conditions.keys()[0])

                for reg in modified_regs:
                    reg64 = reg

                    # x64: rax, eax reg[-2:] == ax
                    if self.arch == "amd64":
                        reg64 = "r" + reg[-2:]
                    conditions[reg64] = values[reg]

                result = self.Verify.verify_path(path, conditions)
                if result:
                    sp, stack = result
                    for return_to_stack_gadget in additional.values():
                        sp += return_to_stack_gadget.move
                    for gadget in path:
                        if "call" == gadget.insns[-1].split()[0]:
                            sp -= self.align
                    sp, stack = self.check_ip_postion(path, conditions, (sp, stack))
                    out.append(("_".join(modified_regs), (path, sp, stack)))
                else:
                    continue

                remain_regs -= modified_regs
                used_regs |= modified_regs

                if remain_regs:
                    gadget_list = re_order(gadget_list, remain_regs)

        if remain_regs:
            log.error("Gadget to regs %r not found!" % list(remain_regs))

        # Top sort to decide the reg order.
        ordered_out = collections.OrderedDict(sorted(out,
                      key=lambda t: self._top_sorted.index(t[1][0][-1].address)))

        ordered_out = self.flat_as_on_stack(ordered_out, additional_conditions)

        return ordered_out

    def check_same_origin(self, path, regs):
        """Only check last gadget in path"""
        last_gadget = path[-1]
        sources = []
        for reg in regs:
            sources.append(str(last_gadget.regs[reg]))

        if len(set(sources)) < len(regs):
            return True

        return False


    def check_ip_postion(self, path, conditions, result):
        sp, stack = result
        large_key = sorted(stack.keys())[-1]
        large_position = large_key/self.align * self.align
        if (large_position > sp - self.align):
            # Need pop the value on large_position, then return to stack
            return_to_stack_gadget = self.get_return_to_stack_gadget(move=large_position-sp+2*self.align)
            conditions[self.PC] = return_to_stack_gadget.address
            result = self.Verify.verify_path(path, conditions)
            sp, stack = result
            sp += return_to_stack_gadget.move

        return sp, stack

    def add_blx_pop_for_arm(self):
        """Similaly to simplify() in gadgetfinder.py file.
        """
        blx_pop_fine    = re.compile(r'^blx r[4-9]; pop \{.*pc\}$')

        gadgets_list = ["; ".join(gadget.insns) for gadget in self.gadgets.values()]
        gadgets_dict = {"; ".join(gadget.insns) : gadget for gadget in self.gadgets.values()}

        def re_match(re_exp):
            result = [gadget for gadget in gadgets_list if re_exp.match(gadget)]
            return sorted(result, key=lambda t:len(t))

        match_list = re_match(blx_pop_fine)

        return [gadgets_dict[i] for i in match_list]


    def flat_a_gadget_without_conditions(self, gadget):
        value_to_flat = {"tail":([gadget],
                                 gadget.move,
                                 {})}
        result = self.flat_as_on_stack(value_to_flat)
        return result["tail"]


    def handle_non_ret_branch(self, path):
        """If last instruction is call xxx/jmp xxx, Handle this scenairo.
        """
        # Inital the result
        condition = {}
        return_to_stack_gadget = None

        # This one for "bx lr"
        exception_operand = "lr"

        front_path = []

        additional = {}
        move = 0
        for gadget in path:
            instr = gadget.insns[-1].split()
            mnemonic   = instr[0]
            if mnemonic == self.CALL or mnemonic == self.JUMP:
                if mnemonic == "call" and 8 > move:
                    move = 8
                elif 4 > move:
                    move = 4

        for i in range(len(path)):
            gadget = path[i]
            instr = gadget.insns[-1].split()
            mnemonic   = instr[0]
            if mnemonic == self.CALL or (mnemonic == self.JUMP and instr[1] != exception_operand):
                pc_reg = gadget.regs[self.PC]
                return_to_stack_gadget = self.get_return_to_stack_gadget(move=move)
                if isinstance(pc_reg, Mem):
                    condition = {self.PC: return_to_stack_gadget.address}

                    additional["; ".join(gadget.insns)] = return_to_stack_gadget
                    front_path += [gadget]

                elif isinstance(pc_reg, (str, unicode)):
                    condition = {pc_reg: return_to_stack_gadget.address}

                    if pc_reg in gadget.regs.keys() and isinstance(gadget.regs[pc_reg], Mem):
                        continue

                    set_value_gadget = self.search_path("sp", [pc_reg])[0]

                    # Handle these issues:
                    # 1. set_value_gadget same as next(i) one or previous(i-1) one, ignore it
                    # 2. set_value_gadget can do the previous do; such as :
                    #       previous        : pop {r0, pc}
                    #       set_value_gadget: pop {r0, r1, pc} need to set r1
                    #       Delete the previous one.
                    # 3. for others:
                    #       If set_value_gadget not the part of path[:i],
                    #       Then, simply insert the set_value_gadget before the last gadget in path.
                    #       Maybe some bugs here, need test cases.

                    # TODO: A problem, set_value_gadget may be overwrited by later's
                    # `set_value_gadget[0] not in front_path` need more testcases
                    if len(set_value_gadget) == 1 and set_value_gadget[0] not in front_path:
                        if front_path and (not (set(front_path[-1].regs.keys()) - set(set_value_gadget[0].regs.keys()))):
                            front_path = front_path[:-1] + set_value_gadget
                        else:
                            front_path += set_value_gadget
                    elif len(set_value_gadget) > 1:
                        if any([x!=y for x,y in zip(set_value_gadget[::-1], front_path[:i][::-1])]):
                            front_path += set_value_gadget

                    additional["; ".join(gadget.insns)] = return_to_stack_gadget
                    front_path += [gadget]

                else:
                    return None
            else:
                front_path += [gadget]

        return (front_path, return_to_stack_gadget, condition, additional)

    def get_return_to_stack_gadget(self, mnemonic="", move=0):
        if mnemonic == "call":
            RET_GAD = re.compile(r'(pop (.{3}); )+ret$')
        else:
            RET_GAD = { "i386"  : re.compile(r'(pop (.{3}); )*ret$'),
                        "amd64" : re.compile(r'(pop (.{3}); )*ret$'),
                        "arm"   : re.compile(r'^pop \{.*pc\}')}[self.arch]

        # Find all matched gadgets, choose the shortest one.
        match_list = [gad for gad in self.gadgets.values() if RET_GAD.match("; ".join(gad.insns)) and gad.move >= move]
        sorted_match_list = sorted(match_list, key=lambda t:len("; ".join(t.insns)))
        if sorted_match_list:
            return sorted_match_list[0]
        else:
            log.error("Cannot find a gadget return to stack.")

    def flat_as_on_stack(self, ordered_dict, additional_conditions={}):
        """Convert the values in ordered_dict to the sequence of stack values.

        Arguments:
            ordered_dict(OrderedDict):
                key is register, value is a tuple, its format as follows:
                    (Gadget_object, sp_move(int), value_on_stack(OrderedDict))

        Return:
            out(list):
                A sequence of stack values.
        """

        out = []

        for reg, result in ordered_dict.items():
            outrop = []
            path, move, _ = result
            sp = 0
            know = {}
            compensate = 0
            path_len = len(path)
            for i in range(path_len):

                gadget = path[i]
                if i == path_len - 1:
                    break

                gad_instr = "; ".join(gadget.insns)
                additional = 0
                if gad_instr in additional_conditions.keys():
                    additional = additional_conditions[gad_instr].move

                # We assume that esp is next to eip, plus `self.align`
                know[sp + gadget.move + additional - self.align] = path[i+1]

                sp += gadget.move + additional

            ropgadget, _, stack_result = result
            outrop.append(ropgadget[0])

            i = 0
            while i < (move - self.align ) or stack_result:
                if i in stack_result.keys():
                    temp_packed = 0
                    for j in range(self.align):
                        temp_packed += stack_result[i+j] << 8*j
                        stack_result.pop(i+j)
                    outrop.append(temp_packed)
                    i += self.align
                elif i in know.keys():
                    outrop.append(know[i])
                    i += self.align
                else:
                    outrop.append(Padding())
                    i += self.align

            out += [(reg, outrop)]

        out = collections.OrderedDict(out)
        return out


    def resolve(self, resolvable):
        """Resolves a symbol to an address

        Arguments:
            resolvable(str,int): Thing to convert into an address

        Returns:
            int containing address of 'resolvable', or None
        """
        if isinstance(resolvable, str):
            for elf in self.elfs:
                if resolvable in elf.symbols:
                    return elf.symbols[resolvable]

        if isinstance(resolvable, (int, long)):
            return resolvable

    def unresolve(self, value):
        """Inverts 'resolve'.  Given an address, it attempts to find a symbol
        for it in the loaded ELF files.  If none is found, it searches all
        known gadgets, and returns the disassembly

        Arguments:
            value(int): Address to look up

        Returns:
            String containing the symbol name for the address, disassembly for a gadget
            (if there's one at that address), or an empty string.
        """
        for elf in self.elfs:
            for name, addr in elf.symbols.items():
                if addr == value:
                    return name

        if value in self.gadgets:
            return '; '.join(self.gadgets[value].insns)
        return ''

    def generatePadding(self, offset, count):
        """
        Generates padding to be inserted into the ROP stack.
        """
        return cyclic.cyclic(offset + count)[-count:]

    def describe(self, object):
        """
        Return a description for an object in the ROP stack
        """
        if isinstance(object, (int, long)):
            return self.unresolve(object)
        if isinstance(object, str):
            return repr(object)
        if isinstance(object, Call):
            return str(object)
        if isinstance(object, Gadget):
            return '; '.join(object.insns)

    def build(self, base = None, description = None):
        """
        Construct the ROP chain into a list of elements which can be passed
        to ``pwnlib.util.packing.flat``.

        Arguments:
            base(int):
                The base address to build the rop-chain from. Defaults to
                :attr:`base`.
            description(dict):
                Optional output argument, which will gets a mapping of
                ``address: description`` for each address on the stack,
                starting at ``base``.
        """

        if base is None:
            base = self.base or 0

        stack = DescriptiveStack(base)
        chain = self._chain

        #
        # First pass
        #
        # Get everything onto the stack and save as much descriptive information
        # as possible.
        #
        # The only replacements performed are to add stack adjustment gadgets
        # (to move SP to the next gadget after a Call) and NextGadgetAddress,
        # which can only be calculated in this pass.
        #
        iterable = enumerate(chain)
        for idx, slot in iterable:

            remaining = len(chain) - 1 - idx
            address   = stack.next

            # Integers can just be added.
            # Do our best to find out what the address is.
            if isinstance(slot, (int, long)):
                stack.describe(self.describe(slot))
                stack.append(slot)


            # Byte blobs can also be added, however they must be
            # broken down into pointer-width blobs.
            elif isinstance(slot, (str, unicode)):
                stack.describe(self.describe(slot))
                slot += self.generatePadding(stack.next, len(slot) % context.bytes)

                for chunk in lists.group(context.bytes, slot):
                    stack.append(chunk)

            elif isinstance(slot, srop.SigreturnFrame):
                stack.describe("Sigreturn Frame")

                if slot.sp in (0, None) and self.base:
                    slot.sp = stack.next + len(slot)

                registers = [slot.registers[i] for i in sorted(slot.registers.keys())]
                for register in registers:
                    value       = slot[register]
                    description = self.describe(value)
                    if description:
                        stack.describe('%s = %s' % (register, description))
                    else:
                        stack.describe('%s' % (register))
                    stack.append(value)

            elif isinstance(slot, Call):
                stack.describe(self.describe(slot))

                # setRegister cannot handle the Constant object args.
                slot.args = [ i if not isinstance(i, constants.Constant) else int(i) for i in slot.args]

                registers    = dict(zip(slot.abi.register_arguments, slot.args))
                tail = None
                operand = ""
                if remaining and self.arch == "arm":
                    func_tail = self.add_blx_pop_for_arm()
                    for gadget in func_tail:
                        operand = gadget.insns[0].split()[1]
                        registers.update({operand : slot.target})
                        try:
                            tail = self.flat_a_gadget_without_conditions(gadget)
                            setRegisters = self.setRegisters(registers)
                            break
                        except:
                            continue

                    if not tail:
                        log.error("Cannot set registers %r properly." % registers)

                else:
                    setRegisters = self.setRegisters(registers)


                for register, gadgets in setRegisters.items():
                    regs        = register.split("_")
                    values      = []
                    for reg in regs:
                        if reg != self.PC and reg != operand:
                            values.append(registers[reg])

                    slot_indexs  = [slot.args.index(v) for v in values]
                    description = " | ".join([self.describe(value) for value in values]) \
                            or 'arg%r' % slot_indexs
                    stack.describe('set %s = %s' % (register, description))
                    stack.extend(gadgets)

                if address != stack.next:
                    stack.describe(slot.name)

                head_or_tail_added = False
                if self.arch == "arm" and remaining > 0  and tail:
                    stack.extend(tail)
                    head_or_tail_added = True

                if not head_or_tail_added:
                    stack.append(slot.target)

                # For any remaining arguments, put them on the stack
                stackArguments = slot.args[len(slot.abi.register_arguments):]
                nextGadgetAddr = stack.next + (context.bytes * len(stackArguments))

                # Generally, stack-based arguments assume there's a return
                # address on the stack.
                #
                # We need to at least put padding there so that things line up
                # properly, but likely also need to adjust the stack past the
                # arguments.
                if slot.abi.returns:
                    if stackArguments:
                        if remaining:
                            fix_size  = (1 + len(stackArguments))
                            fix_bytes = fix_size * context.bytes
                            adjust   = self.search(move = fix_bytes)

                            if not adjust:
                                log.error("Could not find gadget to adjust stack by %#x bytes" % fix_bytes)

                            nextGadgetAddr = stack.next + adjust.move

                            stack.describe('<adjust: %s>' % self.describe(adjust))
                            stack.append(adjust.address)

                            for pad in range(fix_bytes, adjust.move, context.bytes):
                                stackArguments.append(Padding())
                        else:
                            stack.describe('<pad>')
                            stack.append(Padding())


                for i, argument in enumerate(stackArguments):

                    if isinstance(argument, NextGadgetAddress):
                        stack.describe("<next gadget>")
                        stack.append(nextGadgetAddr)

                    else:
                        description = self.describe(argument) or 'arg%i' % (i + len(registers))
                        stack.describe(description)
                        stack.append(argument)
            else:
                stack.append(slot)
        #
        # Second pass
        #
        # All of the register-loading, stack arguments, and call addresses
        # are on the stack.  We can now start loading in absolute addresses.
        #
        start = base
        end   = stack.next
        size  = (stack.next - base)
        for i, slot in enumerate(stack):
            slot_address = stack.address + (i * context.bytes)
            if isinstance(slot, (int, long)):
                pass

            elif isinstance(slot, (str, unicode)):
                pass

            elif isinstance(slot, AppendedArgument):
                stack[i] = stack.next
                stack.extend(slot.resolve(stack.next))

            elif isinstance(slot, CurrentStackPointer):
                stack[i] = slot_address

            elif isinstance(slot, Padding):
                stack[i] = self.generatePadding(i * context.bytes, context.bytes)
                stack.describe('<pad>', slot_address)

            elif isinstance(slot, Gadget):
                stack[i] = slot.address
                stack.describe(self.describe(slot), slot_address)

            # Everything else we can just leave in place.
            # Maybe the user put in something on purpose?
            # Also, it may work in pwnlib.util.packing.flat()
            else:
                pass

        return stack


    def find_stack_adjustment(self, slots):
        self.search(move=slots * context.arch)

    def chain(self):
        """Build the ROP chain

        Returns:
            str containing raw ROP bytes
        """
        return packing.flat(self.build(), word_size=8 * self.align)

    def dump(self):
        """Dump the ROP chain in an easy-to-read manner"""
        return self.build().dump()

    def regs(self, registers=None, **kw):
        if registers is None:
            registers = {}
        registers.update(kw)



    def call(self, resolvable, arguments = (), abi = None, **kwargs):
        """Add a call to the ROP chain

        Arguments:
            resolvable(str,int): Value which can be looked up via 'resolve',
                or is already an integer.
            arguments(list): List of arguments which can be passed to pack().
                Alternately, if a base address is set, arbitrarily nested
                structures of strings or integers can be provided.
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')

        # If we can find a function with that name, just call it
        if isinstance(resolvable, str):
            addr = self.resolve(resolvable)
        else:
            addr = resolvable
            resolvable = ''

        if addr:
            self.raw(Call(resolvable, addr, arguments, abi))

        # Otherwise, if it is a syscall we might be able to call it
        elif not self._srop_call(resolvable, arguments):
            log.error('Could not resolve %r.' % resolvable)



    def _srop_call(self, resolvable, arguments):
        # Check that the call is a valid syscall
        resolvable    = 'SYS_' + resolvable.lower()
        syscall_number = getattr(constants, resolvable, None)
        if syscall_number is None:
            return False

        log.info_once("Using sigreturn for %r" % resolvable)

        # Find an int 0x80 or similar instruction we can use
        syscall_gadget       = None
        syscall_instructions = srop.syscall_instructions[context.arch]

        for instruction in syscall_instructions:
            syscall_gadget = self.find_gadget([instruction])
            if syscall_gadget:
                break
        else:
            log.error("Could not find any instructions in %r" % syscall_instructions)

        # Generate the SROP frame which would invoke the syscall
        with context.local(arch=self.arch):
            frame         = srop.SigreturnFrame()
            frame.pc      = syscall_gadget
            frame.syscall = syscall_number
            SYS_sigreturn  = constants.SYS_sigreturn
            for register, value in zip(frame.arguments, arguments):
                frame[register] = value

        # Set up a call frame which will set EAX and invoke the syscall
        call = Call('SYS_sigreturn',
                    syscall_gadget,
                    [SYS_sigreturn],
                    abi.ABI.sigreturn())

        self.raw(call)
        self.raw(frame)


        # We do not expect to ever recover after the syscall, as it would
        # require something like 'int 0x80; ret' which does not ever occur
        # in the wild.
        self.migrated = True

        return True

    def find_gadget(self, instructions):
        """
        Returns a gadget with the exact sequence of instructions specified
        in the ``instructions`` argument.
        """
        for gadget in self.gadgets.values():
            if tuple(gadget.insns) == tuple(instructions):
                return gadget

    def raw(self, value):
        """Adds a raw integer or string to the ROP chain.

        If your architecture requires aligned values, then make
        sure that any given string is aligned!

        Arguments:
            data(int/str): The raw value to put onto the rop chain.
        """
        if self.migrated:
            log.error('Cannot append to a migrated chain')
        self._chain.append(value)

    def migrate(self, next_base):
        """
        A simple implementation for setting $sp.

        >>> context.clear(arch='i386')
        >>> assembly = "pop ebp; ret;"
        >>> assembly += "leave; ret"
        >>> r = ROP(ELF.from_assembly(assembly))

        Migrate stack to 0x0:

        >>> r.migrate(0)
        >>> print r.dump()
        0x0000:       0x10000000 pop ebp; ret
        0x0004:       0xfffffffc
        0x0008:       0x10000002 leave; ret
        0x000c:           'daaa' <pad>

        """

        if isinstance(next_base, ROP):
            next_base = self.base

        # TODO: hardcode self.align, only for `ret` and `pop {xx, pc}`
        # Not suitable for ret imm16/call reg/jmp reg
        condition = {self.SP : next_base + self.align}
        result = self.setRegisters(condition)[self.SP]
        for item in result:
            self.raw(item)
        self.migrated = True

    def __str__(self):
        """Returns: Raw bytes of the ROP chain"""
        return self.chain()

    def __repr__(self):
        return 'ROP(%r)' % self.elfs

    def search_iter(self, move=None, regs=None):
        """
        Iterate through all gadgets which move the stack pointer by
        *at least* ``move`` bytes, and which allow you to set all
        registers in ``regs``.
        """
        move = move or 0
        regs = set(regs or ())

        for addr, gadget in self.gadgets.items():
            if gadget.insns[-1].split()[0] != self.RET: continue
            if gadget.move < move:          continue
            if not (regs <= set(gadget.regs)):   continue
            yield gadget

    def search(self, move = 0, regs = None, order = 'size'):
        """Search for a gadget which matches the specified criteria.

        Arguments:
            move(int): Minimum number of bytes by which the stack
                pointer is adjusted.
            regs(list): Minimum list of registers which are popped off the
                stack.
            order(str): Either the string 'size' or 'regs'. Decides how to
                order multiple gadgets the fulfill the requirements.

        The search will try to minimize the number of bytes popped more than
        requested, the number of registers touched besides the requested and
        the address.

        If ``order == 'size'``, then gadgets are compared lexicographically
        by ``(total_moves, total_regs, addr)``, otherwise by ``(total_regs, total_moves, addr)``.

        Returns:
            A ``pwnlib.rop.gadgets.Gadget`` object
        """
        matches = self.search_iter(move, regs)
        if matches is None:
            return None

        # Search for an exact match, save the closest match
        key = {
            'size': lambda g: (g.move, len(g.regs), g.address),
            'regs': lambda g: (len(g.regs), g.move, g.address)
        }[order]

        try:
            result = min(matches, key=key)
        except ValueError:
            return None

        # Check for magic 9999999... value used by 'leave; ret'
        if move and result.move == 9999999999:
            return None

        return result

    def __getattr__(self, attr):
        """Helper to make finding ROP gadets easier.

        Also provides a shorthand for ``.call()``:
            ``rop.function(args)`` is equivalent to ``rop.call(function, args)``

        >>> assembly  = 'pop eax; ret;'
        >>> assembly += 'pop ebx; ret;'
        >>> assembly += 'pop ecx; ret;'
        >>> assembly += 'pop edx; ret;'
        >>> assembly += 'pop eax; pop ebx; ret;'
        >>> assembly += 'pop eax; pop ecx; pop ebx; ret;'
        >>> assembly += 'leave;'
        >>> assembly += 'ret;'
        >>> rop = ROP(ELF.from_assembly(assembly))
        >>> rop.eax == rop.search_path("esp", regs=['eax'])
        True
        >>> rop.eax_ecx_ebx == rop.search_path("esp", regs=['eax', 'ecx', 'ebx'])
        True
        >>> rop.ret_8 == rop.search(move=8)
        True
        >>> rop.ret != None
        True
        """
        gadget = collections.namedtuple('gadget', ['address', 'details'])
        bad_attrs = [
            'trait_names',          # ipython tab-complete
            'download',             # frequent typo
            'upload',               # frequent typo
        ]

        if attr in self.__dict__ \
        or attr in bad_attrs \
        or attr.startswith('_'):
            raise AttributeError('ROP instance has no attribute %r' % attr)

        #
        # Check for 'ret' or 'ret_X'
        #
        if attr.startswith('ret'):
            count = 4
            if '_' in attr:
                count = int(attr.split('_')[1])
            return self.search(move=count)

        if attr in ('int80', 'syscall', 'sysenter'):
            mapping = {'int80': 'int 0x80',
             'syscall': 'syscall',
             'sysenter': 'sysenter'}
            for each in self.gadgets:
                if self.gadgets[each]['insns'] == [mapping[attr]]:
                    return gadget(each, self.gadgets[each])
            return None

        #
        # Check for a '_'-delimited list of registers
        #
        reg_suffixes = []
        if self.arch == "i386" or self.arch == "amd64":
            reg_suffixes = ['ax', 'bx', 'cx', 'dx', 'bp', 'sp', 'di', 'si',
                            'r8', 'r9', '10', '11', '12', '13', '14', '15']
        elif self.arch == "arm":
            reg_suffixes = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
                            "10", "11", "12", "13", "14", "15", "sp", "lr", "pc", "fp"]

        if all(map(lambda x: x[-2:] in reg_suffixes, attr.split('_'))):
            regs = attr.split('_')
            gadgets = self.search_path(self.SP, regs)
            return gadgets

        #
        # Otherwise, assume it's a rop.call() shorthand
        #
        def call(*args):
            return self.call(attr, args)

        return call

    def build_graph(self, gadgets):
        '''Build gadgets graph, gadget as vertex, reg as edge.

        Arguments:

            gadgets(dict):
                { address: Gadget object }

        Returns: dict, Graph in adjacency list format.

        Example:

        Assume we have the following gadgets.

        Gadget01 ==> 1000: pop eax; ret
        Gadget02 ==> 2000: mov ebx, eax; ret
        Gadget03 ==> 3000: pop ecx; ret
        Gadget04 ==> 4000: mov edx, ebx; ret

        The gadget graph will looks like this:
        {Gadget01: [Gadget02],
        Gadget02: [Gadget04],
        Gadget03: [],
        Gadget04: []}
        '''

        G = networkx.DiGraph()
        G.add_nodes_from(gadgets.keys())

        gadget_input = {}
        for gad in gadgets.values():
            inputs = []
            for k, i in gad.regs.items():

                # Drop gadgets which set to themselves.
                # For {"esp":["esp"]} or {"eax":"eax"}
                if isinstance(i, (str, unicode)):
                    if k != i:
                        inputs.append(i)
                elif isinstance(i, list):
                    if k != "".join(i):
                        inputs += i

            gadget_input[gad.address] = inputs

        pool = Pool()

        allgadgets = gadgets.values()
        core_number = cpu_count()

        # Need plus one, if not, we will miss some gadgets
        interval = len(allgadgets)/core_number + 1
        gad_inputs = [allgadgets[i*interval : (i+1)*interval] for i in range(core_number)]

        arguments = zip(gad_inputs,
                        repeat(gadgets),
                        repeat(gadget_input))
        if not arguments:
            return {}

        result = pool.map(build_graph_single, arguments)

        results = reduce(lambda x, y: x+y, result)

        for x in results:
            G.add_edge(*x)
            if not networkx.is_directed_acyclic_graph(G):
                G.remove_edge(*x)

        return G

    def search_path(self, src, regs):
        '''Search paths, from src to regs.
        Example: search("rsp", ["rdi"]), such as gadget "pop rdi; ret" will be return to us.
        '''
        start = set()
        for gadget in self.gadgets.values():
            gadget_srcs = []
            for k,i in gadget.regs.items():
                if isinstance(i , Mem):
                    gadget_srcs.append(i.reg)
                elif isinstance(i, list):
                    if all([k!=j for j in i]):
                        gadget_srcs.extend([str(x) for x in i])
                elif isinstance(i, str):
                    if k != i:
                        gadget_srcs.append(i)
            if any([src in i for i in gadget_srcs]):
                start.add(gadget)

        end = set()
        alldst = {}
        for reg in regs:
            alldst[reg] = set()

        asm_instr_dict = {}
        for gadget in self.gadgets.values():
            the_insns = "; ".join(gadget.insns)
            asm_instr_dict[the_insns] = gadget
            gadget_dsts = []
            for k, i in gadget.regs.items():
                if isinstance(i, list):
                    if all([k!=j for j in i]):
                        gadget_dsts.append(k)
                elif isinstance(i, str):
                    if k != i:
                        gadget_dsts.append(k)
                else:
                    gadget_dsts.append(k)

            for reg in regs:
                # x64: rax, eax reg[-2:] == ax
                # r0, r1... length 2, not a problem.
                if any([reg[-2:] in x for x in gadget_dsts]):
                    alldst[reg].add(the_insns)

        dstlist = alldst.values()
        results = reduce(set.intersection, dstlist)
        for r in results:
            end.add(asm_instr_dict[r])

        paths = []
        if len(start) != 0 and len(end) != 0:
            for s in list(start):
                for e in list(end):
                    if s.address  == e.address:
                        paths.append([s.address])
                    else:
                        try:
                            path = networkx.all_shortest_paths(self.gadget_graph,
                                                               source=s.address,
                                                               target=e.address)
                            paths += list(path)
                        except networkx.exception.NetworkXNoPath:
                            continue

        outs = []
        for path in paths:
            out = []
            for p in path:
                out.append(self.gadgets[p])
            outs.append(out)

        paths = outs

        paths = sorted(paths,
                key=lambda path: len(" + ".join(["; ".join(gad.insns) for gad in path])))[:10]

        # Give every reg a random num
        cond = {}
        for reg in regs:
            cond[reg] = random.randint(2**16, 2**32)

            # x64: rax, eax reg[-2:] == ax
            if self.arch == "amd64":
                reg64 = "r" + reg[-2:]
                if reg != reg64:
                    cond[reg64] = random.randint(2**16, 2**32)

        # Solve this gadgets arrangement, if stack's value not changed, ignore it.
        path_filted = []
        for path in paths:
            out = self.Verify.verify_path(path, cond)
            if out:
                path_filted.append(path)

        return path_filted


def build_graph_single((gad_inputs, gadgets, gadget_input)):
    """Child process for build_graph() method.
    """
    edges = []
    for gad_1 in gad_inputs:
        outputs = []
        for i in gad_1.regs.keys():
            if "ip" in i or "pc" in i:
                continue

            if isinstance(i, (str, unicode)):
                # Drop gadgets which set to themselves.
                # For {"esp":["esp"]} or {"eax":"eax"}
                in_reg = gad_1.regs[i]
                if isinstance(in_reg, list):
                    in_reg = "".join(in_reg)

                if in_reg != i:
                    outputs.append(i)

        if not outputs:
            continue

        for gad_2 in gadgets.values():
            if gad_1 == gad_2:
                continue

            inputs = gadget_input[gad_2.address]
            if not inputs:
                continue

            flag = False
            for j in inputs:
                if j in outputs:
                    flag = True
                    break
            if flag:
                edges.append((gad_1.address, gad_2.address))

    return edges
