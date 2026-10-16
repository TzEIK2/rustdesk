# NASM is required to build AOM
vcpkg_find_acquire_program(NASM)
get_filename_component(NASM_EXE_PATH ${NASM} DIRECTORY)
vcpkg_add_to_path(${NASM_EXE_PATH})

# Perl is required to build AOM
vcpkg_find_acquire_program(PERL)
get_filename_component(PERL_PATH ${PERL} DIRECTORY)
vcpkg_add_to_path(${PERL_PATH})

# aom is taken as a tarball from a GitHub mirror instead of a git clone, because the upstream
# host aomedia.googlesource.com refuses git smart-http with HTTP 503 from CI runners often
# enough that `vcpkg_from_git` there aborts the whole install. The mirror holds the unmodified
# upstream tree, so the patches below still apply. The download is deliberately left without a
# hash: GitHub regenerates its archives, so a pinned hash would eventually stop matching. To
# go back to upstream, replace the URLS entry below with
# "https://aomedia.googlesource.com/aom/+archive/${AOM_REF}.tar.gz".
set(AOM_MIRROR_URL "https://github.com/imazen/libaom-mirror")

if(DEFINED ENV{USE_AOM_391})
    set(AOM_CONFIG_PATH "lib/cmake/aom")
    set(AOM_REF "8ad484f8a18ed1853c094e7d3a4e023b2a92df28") # 3.9.1
    set(AOM_PATCHES
            aom-uninitialized-pointer-3.9.1.diff
            aom-avx2.diff
            aom-install.diff)
else()
    set(AOM_CONFIG_PATH "lib/cmake/AOM")
    set(AOM_REF "03087864cf4bea6abb0d28f95cf7843511413d8f") # 3.14.1
    set(AOM_PATCHES
            aom-uninitialized-pointer.diff)
endif()

vcpkg_download_distfile(
    AOM_ARCHIVE
    URLS "${AOM_MIRROR_URL}/archive/${AOM_REF}.tar.gz"
    FILENAME "aom-${AOM_REF}.tar.gz"
    SKIP_SHA512
)

vcpkg_extract_source_archive(
    SOURCE_PATH
    ARCHIVE "${AOM_ARCHIVE}"
    PATCHES ${AOM_PATCHES}
)

set(aom_target_cpu "")
if(VCPKG_TARGET_IS_UWP OR (VCPKG_TARGET_IS_WINDOWS AND VCPKG_TARGET_ARCHITECTURE MATCHES "^arm"))
    # UWP + aom's assembler files result in weirdness and build failures
    # Also, disable assembly on ARM and ARM64 Windows to fix compilation issues.
    set(aom_target_cpu "-DAOM_TARGET_CPU=generic")
endif()

if(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm" AND VCPKG_TARGET_IS_LINUX)
  set(aom_target_cpu "-DENABLE_NEON=OFF")
endif()

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
    OPTIONS
        ${aom_target_cpu}
        -DENABLE_DOCS=OFF
        -DENABLE_EXAMPLES=OFF
        -DENABLE_TESTDATA=OFF
        -DENABLE_TESTS=OFF
        -DENABLE_TOOLS=OFF
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

vcpkg_fixup_pkgconfig()

if(VCPKG_TARGET_IS_WINDOWS)
  vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/lib/pkgconfig/aom.pc" " -lm" "")
  if(NOT VCPKG_BUILD_TYPE)
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig/aom.pc" " -lm" "")
  endif()
endif()

# Move cmake configs
vcpkg_cmake_config_fixup(CONFIG_PATH ${AOM_CONFIG_PATH})

# Remove duplicate files
file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include
                    ${CURRENT_PACKAGES_DIR}/debug/share)

# Handle copyright
file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)

vcpkg_fixup_pkgconfig()
