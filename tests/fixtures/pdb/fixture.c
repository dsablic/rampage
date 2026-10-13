volatile int pdb_value;

__declspec(noinline) static int pdb_local(int value) {
    return value * 3 + 1;
}

__declspec(noinline) int pdb_mix(int left, int right) {
    return pdb_local(left) + right;
}

__declspec(dllexport) __declspec(noinline) int pdb_export(int value) {
    return value + 7;
}

void pdb_entry(void) {
    pdb_value = pdb_mix(4, 9) + pdb_export(2);
}
