import sark
import idaapi
import idc
import idautils
import encoding

class EncodingPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = 'AArch32 Encoding Plugin'
    help = 'Display AArch32 instruction encoding'
    wanted_name = 'AArch32_Encoding'
    wanted_hotkey = 'Ctrl+E'

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        l = sark.Line()
        enc = encoding.Encodings().find_inst(l.bytes, idc.GetReg(l.ea, 'T') == 1)
        print("line '%s' at %08x enc:\n%s\n" % (idc.GetMnem(l.ea), l.ea, enc))

def PLUGIN_ENTRY():
    return EncodingPlugin()
