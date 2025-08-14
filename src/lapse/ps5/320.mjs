/* Copyright (C) 2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// 3.20

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x2ced0,
    pthread_join: 0x2f460,
    pthread_barrier_init: 0xd930,
    pthread_barrier_wait: 0x26040,
    pthread_barrier_destroy: 0x129b0,
    pthread_exit: 0x20a80,
  }),
);

export const kernel_offsets = new Map(
  Object.entries({
    data_base: 0x0BD0000,
    data_size: 0x08871930,

    data_base_dynamic: 0x00010000,
    data_base_to_dynamic: 0x067D1B90,
    data_base_allproc: 0x0276DC58,
    data_base_security_flags: 0x06466474,
    data_base_rootvnode: 0x067AB4C0,
    data_base_kernel_pmap_store: 0x031BE218,
    data_base_data_cave: 0x06140000,  // Unconfirmed
    data_base_gvmspace: 0x06423F80,

    pmap_store_pml4pml4i: -0x1C,
    pmap_store_dmpml4i: 0x288,
    pmap_store_dmpdpi: 0x28C,
  })
);

export const off_longjmp = 0x5F990;
export const off_sceKernelRaiseException = 0x18A30;

// export const off_kstr = null;
// export const off_cpuid_to_pcpu = null;

// export const jmp_rsi = null;

// export const patch_elf_loc = "./kpatch/320.bin"; // Relative to `../../lapse.mjs`
