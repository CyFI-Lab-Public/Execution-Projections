from __future__ import annotations
import logging

from angr.storage.file import SimFileDescriptorDuplex
from angr.procedures.stubs.format_parser import FormatParser

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

l = logging.getLogger(name=__name__)


class fprintf(FormatParser):
    def run(self, file_ptr, fmt, *args):
        print(f"[fprintf] custom symbolic procedure")
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]

        # Check if file_ptr is an address or resolve it to one if possible
        try:
            # Attempt to retrieve an address if `file_ptr` is a `SimFileDescriptorDuplex`
            print(f"\tis_SimFileDescriptorDuplex: {isinstance(file_ptr, SimFileDescriptorDuplex)}")
            if isinstance(file_ptr, SimFileDescriptorDuplex):
                file_ptr_addr = file_ptr.read_pos if hasattr(file_ptr, "read_pos") else None
            else:
                file_ptr_addr = file_ptr  # Assume file_ptr is already an address

            print(f"\tfile_ptr_addr: {file_ptr_addr}")
            print(f"\tfd_offset: {fd_offset}")
            print(f"\tfmt: {fmt}")
            # Verify file_ptr_addr is valid before proceeding
            if file_ptr_addr is None:
                raise TypeError("file_ptr could not be resolved to a valid address")
            
            # Now perform the addition using the resolved address
            fileno = self.state.mem[file_ptr_addr + fd_offset :].int.resolved

        except TypeError:
            print("TypeError: file_ptr is not a valid address.")
            return -1  # Or handle the error in a suitable way
        
        # fileno = self.state.mem[file_ptr + fd_offset :].int.resolved    # XXX: TypeError: unsupported operand type(s) for +: 'SimFileDescriptorDuplex' and 'int'
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1

        # The format str is at index 1
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(lambda *args: self.va_arg(*args), *args)

        simfd.write_data(out_str, out_str.size() // 8)

        return out_str.size() // 8
