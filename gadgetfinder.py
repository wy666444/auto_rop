# -*- coding: utf-8 -*-

import re
import os
import copy
import types
import string
import hashlib
import tempfile
import operator

from ..context  import context, LocalContext
from ..asm     import *
from ..log     import getLogger
from ..elf     import ELF
from .gadgets  import Gadget, Mem

from multiprocessing import Pool
from BTrees.OOBTree import OOBTree
from amoco.cas.expressions import *
from z3          import *
from collections import OrderedDict
from operator    import itemgetter
from capstone    import CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB
from capstone    import Cs, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET
from itertools   import repeat

log = getLogger(__name__)

# File size more than 100kb, should be filter for performance trade off
MAX_SIZE = 200


class GadgetMapper(object):
    r"""Get the gadgets mapper in symbolic expressions.

    This is the base class for GadgetSolver and GadgetClassifier.

    """

    @LocalContext
    def __init__(self, arch, mode):
        '''Base class which can symbolic execution gadget instructions.
        '''
        self.arch = arch

        if arch == CS_ARCH_X86 and mode == CS_MODE_32:
            import amoco.arch.x86.cpu_x86 as cpu
        elif arch == CS_ARCH_X86 and mode == CS_MODE_64:
            import amoco.arch.x64.cpu_x64 as cpu
        elif arch == CS_ARCH_ARM:
            import amoco.arch.arm.cpu_armv7 as cpu
        else:
            raise Exception("Unsupported archtecture %s." % arch)

        self.cpu = cpu
        self.align = context.bits / 8

        self.CALL = {CS_ARCH_X86: "call",   CS_ARCH_ARM: "blx"}[self.arch]
        self.FLAG = {CS_ARCH_X86: "flags",  CS_ARCH_ARM: "apsr"}[self.arch]
        self.RET  = {CS_ARCH_X86: "ret",    CS_ARCH_ARM: "pop"}[self.arch]
        self.JMP  = {CS_ARCH_X86: "jmp",    CS_ARCH_ARM: "bx"}[self.arch]
        self.SP   = {CS_ARCH_X86: "sp",     CS_ARCH_ARM: "sp"}[self.arch]
        self.IP   = {CS_ARCH_X86: "ip",     CS_ARCH_ARM: "pc"}[self.arch]


    @LocalContext
    def sym_exec_gadget_and_get_mapper(self, code, state=0):
        r'''This function gives you a ``mapper`` object from assembled `code`.
        `code` will basically be our assembled gadgets.

        Arguments:
            code(str): The raw bytes of gadget which you want to symbolic execution.

        Return:
            A mapper object.

        Example:

        >>> context.clear(arch="amd64")
        >>> se = GadgetMapper(CS_ARCH_X86, CS_MODE_64)
        >>> print se.sym_exec_gadget_and_get_mapper(asm("pop rdi; ret"))
        rdi <- { | [0:64]->M64(rsp) | }
        rsp <- { | [0:64]->(rsp+0x10) | }
        rip <- { | [0:64]->M64(rsp+8) | }

        Note that `call`s will be neutralized in order to not mess-up the
        symbolic execution (otherwise the instruction just after the `call`
        is considered as the instruction being jumped to).

        From this ``mapper`` object you can reconstruct the symbolic CPU state
        after the execution of your gadget.

        The CPU used is x86, but that may be changed really easily, so no biggie.

        Taken from https://github.com/0vercl0k/stuffz/blob/master/look_for_gadgets_with_equations.py'''
        if self.arch == CS_ARCH_ARM:
            from amoco.arch.arm.v7.env import internals
            internals["isetstate"] = state

        import amoco
        import amoco.system.raw
        import amoco.system.core

        p = amoco.system.raw.RawExec(
            amoco.system.core.DataIO(code), self.cpu
        )

        try:
            blocks = list(amoco.lsweep(p).iterblocks())
        except:
            return None

        if len(blocks) == 0:
            return None

        mp = amoco.cas.mapper.mapper()
        for block in blocks:
            # If the last instruction is a call, we need to "neutralize" its effect
            # in the final mapper, otherwise the mapper thinks the block after that one
            # is actually 'the inside' of the call, which is not the case with ROP gadgets
            if block.instr[-1].mnemonic.lower() == 'call':
                p.cpu.i_RET(None, block.map)

            try:
                mp >>= block.map
            except Exception as e:
                pass

        return mp

class GadgetClassifier(GadgetMapper):
    r"""Classify gadgets to decide its sp_move value and regs relationship.
    """

    def __init__(self, arch, mode):
        super(GadgetClassifier, self).__init__(arch, mode)


    def classify(self, gadget):
        r"""Classify gadgets, get the regs relationship, and sp move.

        Arguments:
            gadget(Gadget object), with sp == 0 and regs = {}

        Return:
            Gadget object with correct sp move value and regs relationship

        Example:

            >>> context.clear(arch='amd64')
            >>> gadget_to_be_classify = Gadget(0x1000, [u'pop rdi', u'ret'], {}, 0x0, "\x5f\xc3")
            >>> gc = GadgetClassifier(CS_ARCH_X86, CS_MODE_64)
            >>> gc.classify(gadget_to_be_classify)
            Gadget(0x1000, [u'pop rdi', u'ret'], {'rsp': ['rsp'], 'rdi': M64(M64(rsp), #0), 'rip': M64(M64(rsp+8), #8)}, 0x10)
        """
        address = gadget.address
        insns   = gadget.insns
        bytes   = gadget.bytes

        # No mapper gadgets will return immediately.
        no_mapper_instr = ["int", "sysenter", "syscall", "svc"]
        last_instr      = insns[-1].split()
        last_mnemonic   = last_instr[0]
        if last_mnemonic in no_mapper_instr and len(insns) == 1:
            return Gadget(address, insns, {}, 0, bytes)

        instruction_state = address & 1
        mapper = self.sym_exec_gadget_and_get_mapper(bytes, state=instruction_state)
        if not mapper:
            return None

        regs = {}
        move = 0
        ip_move = 0

        first_instr      = insns[0].split()
        first_mnemonic   = first_instr[0]

        if first_mnemonic == self.CALL:
            regs["pc_temp"] = first_instr[1]

        last_instr      = insns[-1].split()
        last_mnemonic   = last_instr[0]

        for reg_out, _ in mapper:
            if last_mnemonic != self.CALL and \
               (reg_out._is_ptr or reg_out._is_mem):
                return None

            if self.FLAG in str(reg_out):
                continue
            try:
                inputs = mapper[reg_out]
            except ValueError:
                return None

            if self.SP in str(reg_out):
                move = extract_offset(inputs)[1]

                # Because call will push the eip/rip onto stack,
                # the Stack will increase.
                if last_mnemonic == self.CALL and self.arch == CS_ARCH_X86:
                    move -= self.align

            if self.IP in str(reg_out):
                if last_mnemonic == self.RET:
                    if isinstance(inputs, mem):
                        ip_move = inputs.a.disp
                    elif isinstance(inputs, op):
                        ip_move = extract_offset(inputs)[1]
                    else:
                        return None
                elif last_mnemonic == self.CALL:
                    opt_str = last_instr[1]
                    regs[str(reg_out)] = opt_str
                    regs["pc_temp"] = opt_str
                    continue
                elif last_mnemonic == self.JMP:
                    opt_str = last_instr[1]
                    regs["pc_temp"] = opt_str
                else:
                    return None

            handled_inputs = self.handle_mapper(inputs)
            regs[str(reg_out)] = handled_inputs

        if self.RET == last_mnemonic and ip_move != (move - self.align):
            return None
        elif not regs and not move:
            return None
        else:
            return Gadget(address, insns, regs, move, bytes)


    def handle_mapper(self, inputs):

        if inputs._is_mem:
            offset = inputs.a.disp
            reg_mem = locations_of(inputs)

            if isinstance(reg_mem, list):
                reg_str = "_".join([str(i) for i in reg_mem])
            else:
                reg_str = str(reg_mem)

            reg_size = inputs.size

            return Mem(reg_str, offset, reg_size)

        elif inputs._is_reg:
            return str(inputs)

        elif inputs._is_cst:
            return inputs.value

        elif isinstance(inputs, list) or isinstance(inputs, types.GeneratorType):
            return  [str(locations_of(i) for i in inputs)]

        else:
            allregs = locations_of(inputs)
            if isinstance(allregs, list):
                allregs = [str(i) for i in allregs]
            elif isinstance(allregs, reg):
                allregs = str(allregs)

            return allregs



class GadgetSolver(GadgetMapper):

    def __init__(self, arch, mode):
        r"""Solver a gadget path to satisfy some conditions.

        Example:

        >>> gadget_path = [Gadget(0x1000, [u'pop rdi', u'ret'], {}, 0x0, "\x5f\xc3")]
        >>> gs = GadgetSolver(CS_ARCH_X86, CS_MODE_64)
        >>> conditions = {"rdi" : 0xbeefdead}
        >>> sp_move, stack_result = gs.verify_path(gadget_path, conditions)
        """
        super(GadgetSolver, self).__init__(arch, mode)

    def _prove(self, expression):
        s = Solver()
        s.add(expression)
        if s.check() == sat:
            return s.model()
        return None

    def verify_path(self, path, conditions={}):
        """Solve a gadget path, get the sp move and which values should be on stack.

        Arguments:

            path(list): Gadgets arrangement from reg1/mem to reg2
                ["pop ebx; ret", "mov eax, ebx; ret"]

            conditions(dict): the result we want.
                {"eax": 0xbeefdead}, after gadgets in path executed, we want to assign 0xbeefdead to eax.

        Returns:

            tuple with two items
            first item is sp move
            second is which value should on stack, before gadgets in path execute
            For the example above, we will get:
                (12, OrderedDict{0:"\xad", 1:"\xde", 2:"\xef", 3:"\xbe"})
        """
        concate_bytes = "".join([gadget.bytes for gadget in path])
        instruction_state = path[0].address & 1
        gadget_mapper = self.sym_exec_gadget_and_get_mapper(concate_bytes, state=instruction_state)

        last_instr      = path[-1].insns[-1].split()
        last_mnemonic   = last_instr[0]

        stack_changed = []
        move = 0
        for reg_out, constraint in gadget_mapper:
            if "sp" in str(reg_out):
                move = extract_offset(gadget_mapper[reg_out])[1]
                # Because call will push the eip/rip onto stack,
                # the Stack will increase.
                if last_mnemonic == self.CALL and self.arch == CS_ARCH_X86:
                    move -= self.align

            if str(reg_out) in conditions.keys():
                model = self._prove(conditions[str(reg_out)] == constraint.to_smtlib())
                if not model:
                    return None

                sp_reg = locations_of(gadget_mapper[reg_out])
                if isinstance(sp_reg, list):
                    sp_reg = [str(i) for i in sp_reg]
                else:
                    sp_reg = str(sp_reg)

                possible_type = [mem, reg, op]
                if any([isinstance(gadget_mapper[reg_out], t) for t in possible_type])\
                   and any(["sp" in i for i in sp_reg]) :
                    try:
                        num = model[model[1]].num_entries()
                        stack_changed += model[model[1]].as_list()[:num]
                    except IndexError:
                        return None
        if len(stack_changed) == 0:
            return None

        stack_converted = [(i[0].as_signed_long(), i[1].as_long()) for i in stack_changed]
        stack_changed = OrderedDict(sorted(stack_converted, key=itemgetter(0)))

        # If we want to set esp/rsp, the total move value will be confused.
        # So we add all the gadgets's move in the path for simply.
        if any(["sp" in x for x in conditions.keys()]):
            move = reduce(lambda x, y: x+ y, [gad.move for gad in path])
        return (move, stack_changed)


class GadgetFinder(object):
    """Finding gadgets for specified elfs.

    Example:

    elf = ELF('path-to-binary')
    gf = GadgetFinder(elf)
    gadgets = gf.load_gadgets()

    """

    @LocalContext
    def __init__(self, input, arch="i386", gadget_filter="all", depth=10):

        if input:
            if isinstance(input, ELF):
                elfs = [input]
            elif isinstance(input, (str, unicode)):
                if os.path.exists(input):
                    elfs = [ELF(input)]
                elif any(x not in string.printable for x in input[:8]):
                    context.arch=arch
                    elfs = [ELF(make_elf(input, extract=False))]
                else:
                    log.error("ROP: input filename not found!")
            elif isinstance(input, (tuple, list)) and isinstance(input[0], ELF):
                elfs = input
            else:
                log.error("ROP: Cannot load such elfs.")

        self.elfs = elfs

        # Maximum instructions lookahead bytes.
        self.depth = depth
        self.gadget_filter = gadget_filter

        x86_gadget = {
                "ret":      [["\xc3", 1, 1],               # ret
                            ["\xc2[\x00-\xff]{2}", 3, 1],  # ret <imm>
                            ],
                "jmp":      [["\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1], # jmp  [reg]
                            ["\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                            ["\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1], # jmp  [reg]
                            ],
                "call":     [["\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1],  # call  [reg]
                            ],
                "int":      [["\xcd\x80", 2, 1], # int 0x80
                            ],
                "sysenter": [["\x0f\x34", 2, 1], # sysenter
                            ],
                "syscall":  [["\x0f\x05", 2, 1], # syscall
                            ]}
        all_x86_gadget = reduce(lambda x, y: x + y, x86_gadget.values())
        x86_gadget["all"] = all_x86_gadget

        arm_gadget = {
                "ret":  [["[\x00-\xff]{1}[\x80-\x8f]{1}\xbd\xe8", 4, 4],       # pop {,pc}
                         ["\x04\xf0\x9d\xe4", 4, 4],                           # pop {pc}
                        ],
                "bx":   [["[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                        ],
                "blx":  [["[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                        ],
                "svc":  [["\x00-\xff]{3}\xef", 4, 4] # svc
                        ],
                }
        all_arm_gadget = reduce(lambda x, y: x + y, arm_gadget.values())
        arm_gadget["all"] = all_arm_gadget

        arm_thumb = {
                "ret": [["[\x00-\xff]{1}\xbd", 2, 2], # pop {,pc}
                    ],
                "bx" : [["[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                    ],
                "blx": [["[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                    ],
                "svc": [["\x00-\xff]{1}\xef", 2, 2], # svc
                    ],
                }
        all_arm_thumb = reduce(lambda x, y: x + y, arm_thumb.values())
        arm_thumb["all"] = all_arm_thumb


        self.arch_mode_gadget = {
                "i386"  : (CS_ARCH_X86, CS_MODE_32,     x86_gadget[gadget_filter]),
                "amd64" : (CS_ARCH_X86, CS_MODE_64,     x86_gadget[gadget_filter]),
                "arm"   : (CS_ARCH_ARM, CS_MODE_ARM,    arm_gadget[gadget_filter]),
                "thumb" : (CS_ARCH_ARM, CS_MODE_THUMB,  arm_thumb[gadget_filter]),
                }

        if self.elfs[0].arch != context.arch:
            log.error("Context arch should be the same as binary arch.")

        data_len = len(self.elfs[0].file.read())

        if context.arch not in self.arch_mode_gadget.keys():
            raise Exception("Architecture not supported.")


        self.arch, self.mode, self.gadget_re = self.arch_mode_gadget[context.arch]
        self.need_filter = False
        if data_len >= MAX_SIZE*1000:
            self.need_filter = True

        self.solver     = GadgetSolver(self.arch, self.mode)


    def load_gadgets(self):
        """Load all ROP gadgets for the selected ELF files
        """

        out = {}
        for elf in self.elfs:

            gadget_db = GadgetDatabase(elf)
            gads = gadget_db.load_gadgets()


            if not gads:
                gg = []
                for seg in elf.executable_segments:
                    self.classifier = GadgetClassifier(self.arch, self.mode)
                    gg += find_all_gadgets_multi_process(seg, self.gadget_re, elf, self.arch, self.mode, self.need_filter)

                    if self.arch == CS_ARCH_ARM:
                        arch, mode, gadget_re = self.arch_mode_gadget["thumb"]
                        self.classifier = GadgetClassifier(arch, mode)
                        gg += find_all_gadgets_multi_process(seg, gadget_re, elf, arch, mode, self.need_filter)

                if self.need_filter:
                    if self.arch == CS_ARCH_X86:
                        gg = self.__simplify_x86(gg)
                    elif self.arch == CS_ARCH_ARM:
                        gg = self.__simplify_arm(gg)
                else:
                    gg = self.__deduplicate(gg)

                if self.need_filter:
                    temp = [self.classifier.classify(gadget) for gadget in gg]
                    gg = [ gadget for gadget in temp if gadget]

                for gadget in gg:
                    out[gadget.address] = gadget

                gg2 = copy.deepcopy(gg)
                gadget_db.save_gadgets(gg2)


            else:
                out.update(gads)

        return out


    def __deduplicate(self, gadgets):
        new, insts = [], []
        for gadget in gadgets:
            insns = "; ".join(gadget.insns)
            if insns in insts:
                continue
            insts.append(insns)
            new += [gadget]
        return new

    def __simplify_x86(self, gadgets):
        """Simplify gadgets, reserve minimizing gadgets set.
        """
        pop_ax  = re.compile(r'^pop .ax; (pop (.{3}); )*ret$')
        pop_bx  = re.compile(r'^pop .bx; (pop (.{3}); )*ret$')
        pop_cx  = re.compile(r'^pop .cx; (pop (.{3}); )*ret$')
        pop_dx  = re.compile(r'^pop .dx; (pop (.{3}); )*ret$')
        pop_di  = re.compile(r'^pop .di; (pop (.{3}); )*ret$')
        pop_si  = re.compile(r'^pop .si; (pop (.{3}); )*ret$')
        pop_r8  = re.compile(r'^pop .r8; (pop (.{3}); )*ret$')
        pop_r9  = re.compile(r'^pop .r9; (pop (.{3}); )*ret$')
        leave   = re.compile(r'^leave; ret$')
        int80 = re.compile(r'int +0x80; (pop (.{3}); )*ret$')
        syscall = re.compile(r'^syscall$')
        sysenter = re.compile(r'^sysenter$')

        re_list = [pop_ax, pop_bx, pop_cx, pop_dx, pop_di, pop_si,
                   pop_r8, pop_r9, leave, int80, syscall, sysenter]

        return simplify(gadgets, re_list)


    def __simplify_arm(self, gadgets):
        """Simplify gadgets, reserve minimizing gadgets set.

        Example:

            gadgets = {
                        "blx r3; pop {r4, pc}", "blx r2; pop {r4, r5, pc}",
                        "blx r5; pop {pc}", "blx r4; pop {r4, pc}",
                        "pop {r0, pc}", "pop {r0, r5, pc}",
                        "pop {r0, r1, pc}", "pop {r0, r1, r3, pc}",
                        "pop {r0, r1, r2, pc}", "pop {r0, r1, r2, r5, pc}",
                        "pop {r0, r1, r2, r3, pc}", "pop {r0, r1, r2, r3, r6, pc}",
                        }

            __simplify_arm(gadgets)
            {   "blx r3; pop {r4, pc}",
                "blx r5; pop {pc}",
                "pop {r0, pc}",
                "pop {r0, r1, pc}",
                "pop {r0, r1, r2, pc}",
                "pop {r0, r1, r2, r3, pc}"}

        """
        blx_pop         = re.compile(r'^blx r[0-3]; pop \{.*pc\}$')
        blx_pop_fine    = re.compile(r'^blx r[4-9]; pop \{.*pc\}$')
        pop_r0          = re.compile(r'^pop \{r0, .*pc\}$')
        pop_r0_r1       = re.compile(r'^pop \{r0, r1, .*pc\}$')
        pop_r0_r1_r2    = re.compile(r'^pop \{r0, r1, r2, .*pc\}$')
        pop_r0_r1_r2_r3 = re.compile(r'^pop \{r0, r1, r2, r3, .*pc\}$')
        bx              = re.compile(r'^bx r[0-4]$')
        pop_lr          = re.compile(r'^pop \{.*lr\}.*pop \{.*pc\}$')
        svc             = re.compile(r'^svc')

        re_list = [blx_pop, blx_pop_fine, pop_r0, pop_r0_r1, pop_r0_r1_r2, pop_r0_r1_r2_r3, bx, pop_lr, svc]

        return simplify(gadgets, re_list)


class GadgetDatabase(object):
    """A Gadget database object to store gadget easily.
    """

    def __init__(self, elf):
        self.elfname = elf.file.name
        self.dbname = self.get_db_name(elf)
        self.db     = self.get_db()
        self.bin_addr = elf.address

    def get_db_name(self, elf):
        sha256   = hashlib.sha256(elf.get_data()).hexdigest()
        cachedir = os.path.join(tempfile.gettempdir(), 'binjitsu-rop-cache')

        if not os.path.exists(cachedir):
            os.mkdir(cachedir)

        return os.path.join(cachedir, sha256)

    def get_db(self):
        import ZODB, ZODB.FileStorage

        storage = ZODB.FileStorage.FileStorage(self.dbname)
        db = ZODB.DB(storage)
        connection = db.open()
        root = connection.root()
        return root

    def save_gadgets(self, gadgets):
        import transaction

        for gadget in gadgets:
            gadget.address -= self.bin_addr

        if not self.db.has_key("gadgets"):
            self.db['gadgets'] = OOBTree()

        gadget_db = self.db["gadgets"]
        for gadget in gadgets:
            gadget_db[gadget.address] = gadget

        transaction.commit()

    def load_gadgets(self):
        out = {}

        if not self.db.has_key("gadgets"):
            return None

        if len(self.db["gadgets"]) == 0:
            return None

        log.info_once("Loaded cached gadgets for %r" % self.elfname)

        result_1={}
        gadgets = self.db["gadgets"]
        result_1.update(gadgets)
        result_2 = copy.deepcopy(result_1)

        for gadget in result_2.values():
            gadget.address += self.bin_addr
            out[gadget.address] = gadget

        return out


def simplify(gadgets, re_list):

    gadgets_list = ["; ".join(gadget.insns) for gadget in gadgets]
    gadgets_dict = {"; ".join(gadget.insns) : gadget for gadget in gadgets}

    def re_match(re_exp):
        result = [gadget for gadget in gadgets_list if re_exp.match(gadget)]
        return sorted(result, key=lambda t:len(t))

    match_list = [re_match(x) for x in re_list]

    out = []
    for i in match_list:
        if i:
            item_01 = i[0]
            out.append(gadgets_dict[item_01])
    return out

def find_all_gadgets_multi_process(section, gadget_re, elf, arch, mode, need_filter):
    '''Find gadgets like ROPgadget do.
    '''
    C_OP = 0

    raw_data = section.data()
    pvaddr = section.header.p_vaddr
    elftype = elf.elftype
    elf_base_addr = elf.address

    pool = Pool()

    arguments = []
    for gad in gadget_re:
        allRef = [m.start() for m in re.finditer(gad[C_OP], raw_data)]
        arguments += zip(repeat(raw_data),
                         repeat(pvaddr),
                         repeat(elftype),
                         repeat(elf_base_addr),
                         repeat(arch),
                         repeat(mode),
                         repeat(gad),
                         repeat(need_filter),
                         allRef)
    if not arguments:
        return []

    results = pool.map(find_single, arguments)
    gadgets = []
    for r in results:
        gadgets += r
    return gadgets


def find_single((raw_data, pvaddr, elftype, elf_base_addr, arch, mode, gad, need_filter, ref)):
    C_OP = 0
    C_SIZE = 1
    C_ALIGN = 2

    allgadgets = []

    md = Cs(arch, mode)
    md.detail = True

    for i in range(10):
        back_bytes = i * gad[C_ALIGN]
        section_start = ref - back_bytes
        start_address = pvaddr + section_start
        if elftype == 'DYN':
            start_address = elf_base_addr + start_address

        decodes = md.disasm(raw_data[section_start : ref + gad[C_SIZE]],
                            start_address)

        decodes = list(decodes)
        insns = []
        for decode in decodes:
            insns.append((decode.mnemonic + " " + decode.op_str).strip())

        if len(insns) > 0:
            if (start_address % gad[C_ALIGN]) == 0:
                address = start_address
                if mode == CS_MODE_THUMB:
                    address = address | 1

                bytes   = raw_data[ref - (i*gad[C_ALIGN]):ref+gad[C_SIZE]]
                onegad = Gadget(address, insns, {}, 0, bytes)
                if not passClean(decodes):
                    continue

                if arch == CS_ARCH_X86:
                    onegad = filter_for_x86_big_binary(onegad)
                elif arch == CS_ARCH_ARM:
                    onegad = filter_for_arm_big_binary(onegad)

                if (not need_filter) and onegad:
                    classifier = GadgetClassifier(arch, mode)
                    onegad = classifier.classify(onegad)

                if onegad:
                    allgadgets += [onegad]

    return allgadgets

def checkMultiBr(decodes, branch_groups):
    """Caculate branch number for __passClean().
    """
    count = 0
    ldm     = re.compile(r"^ldm.*sp!, \{.*\}")
    pop_pc  = re.compile('^pop.* \{.*pc\}')
    for inst in decodes:
        insns = inst.mnemonic + " " + inst.op_str
        if pop_pc.match(insns):
            count += 1
        elif ldm.match(insns):
            count += 1

        for group in branch_groups:
            if group in inst.groups:
                count += 1
    return count

def passClean(decodes, multibr=False):
    """Filter gadgets with two more blocks.
    """

    branch_groups = [CS_GRP_JUMP,
                     CS_GRP_CALL,
                     CS_GRP_RET,
                     CS_GRP_INT,
                     CS_GRP_IRET]

    # "pop {.*pc}" for arm
    # Because Capstone cannot identify this instruction as Branch instruction
    blx     = re.compile('^blx ..$')
    pop_pc  = re.compile('^pop \{.*pc\}')
    call    = re.compile(r'^call ...$')
    int80   = re.compile(r'int +0x80')
    ret     = re.compile(r'^ret$')
    svc     = re.compile(r'^svc$')
    ldm     = re.compile(r"^ldm.*sp!, \{.*\}")

    first_instr = (decodes[0].mnemonic + " " + decodes[0].op_str)
    last_instr  = (decodes[-1].mnemonic + " " + decodes[-1].op_str)

    # For gadgets as follows:
    # 1. call reg; xxx; ret
    # 2. blx reg; xxx; pop {.*pc}
    # 3. int 0x80; xxx; ret
    # 4. svc; xxx; pop {.*pc}
    if call.match(first_instr) and ret.match(last_instr):
        return True
    if blx.match(first_instr) and pop_pc.match(last_instr):
        return True
    if int80.match(first_instr) and ret.match(last_instr):
        return True
    if svc.match(first_instr) and pop_pc.match(last_instr):
        return True

    if len(decodes) > 5:
        return False

    if (not pop_pc.match(last_instr)) and (not ldm.match(last_instr)) and (not (set(decodes[-1].groups) & set(branch_groups))):
        return False

    branch_num = checkMultiBr(decodes, branch_groups)
    if not multibr and (branch_num > 1 or branch_num == 0):
        return False

    return True

def filter_for_x86_big_binary(gadget):
    '''Filter gadgets for big binary.
    '''
    new = None
    pop   = re.compile(r'^pop (.{3})')
    add   = re.compile(r'^add .sp, (\S+)')
    ret   = re.compile(r'^ret$')
    leave = re.compile(r'^leave$')
    mov   = re.compile(r'^mov (.{3}), (.{3})$')
    xchg  = re.compile(r'^xchg (.{3}), (.{3})$')
    int80 = re.compile(r'int +0x80')
    syscall = re.compile(r'^syscall$')
    sysenter = re.compile(r'^sysenter$')
    call  = re.compile(r'^call (.{3})$')
    jmp   = re.compile(r'^jmp (.{3})$')
    push  = re.compile(r'^push (.{3})')
    dec   = re.compile(r'^dec (.{3})')
    inc   = re.compile(r'^inc (.{3})')
    mov_ptr   = re.compile(r'^mov (.{3}), .word ptr \[(.{3}).*\]$')


    valid = lambda insn: any(map(lambda pattern: pattern.match(insn),
        [pop,add,ret,leave,xchg,mov,int80,syscall,sysenter,call,jmp,push,dec,inc,mov_ptr]))

    insns = gadget.insns
    if all(map(valid, insns)):
        new = gadget

    return new

def filter_for_arm_big_binary(gadget):
    '''Filter gadgets for big binary.
    '''
    new = None
    poppc = re.compile(r'^pop \{.*pc\}$')
    blx   = re.compile(r'^blx (.{2})$')
    bx    = re.compile(r'^bx (.{2})$')
    poplr = re.compile(r'^pop \{.*lr\}$')
    mov   = re.compile(r'^mov (.{2}), (.{2})$')
    svc   = re.compile(r'^svc$')
    add   = re.compile(r'^add (.{2}).*')

    valid = lambda insn: any(map(lambda pattern: pattern.match(insn),
        [poppc,blx,bx,poplr,mov,svc,add]))

    insns = gadget.insns
    if all(map(valid, insns)):
        new = gadget

    return new
