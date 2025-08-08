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

// 8.52

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x2CED0,
    pthread_join: 0x2F460,
    // pthread_barrier_init: 0x283d0,
    // pthread_barrier_wait: 0xb8c0,
    // pthread_barrier_destroy: 0x9c10,
    pthread_exit: 0x20A80,
  }),
);

// export const off_kstr = null;
// export const off_cpuid_to_pcpu = null;

// export const jmp_rsi = null;

// export const patch_elf_loc = "./kpatch/320.bin"; // Relative to `../../lapse.mjs`
