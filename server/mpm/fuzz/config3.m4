APACHE_MPMPATH_INIT(fuzz)

fuzz_objects="fuzz_api.lo fuzz_core.lo"

APACHE_MPM_MODULE(fuzz, $enable_mpm_fuzz, $fuzz_objects)

APACHE_MPMPATH_FINISH
