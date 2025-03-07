# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: Apache-2.0

find_program(clang_path "clang" REQUIRED)

execute_process(
  COMMAND echo "int main() { return 0;}"
  COMMAND ${clang_path} --target=bpf -x c - -c -o /dev/null
  ERROR_QUIET OUTPUT_QUIET
  RESULT_VARIABLE CLANG_RETURN_CODE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (CLANG_RETURN_CODE EQUAL 0)
    message(STATUS "Clang supports BPF target")
    set(CLANG_SUPPORTS_BPF TRUE)
else()
    message(WARNING "Clang does not support BPF target, skipping BPF tests")
    set(CLANG_SUPPORTS_BPF FALSE)
endif()

function(build_bpf file_name)
    message(STATUS "Building BPF ${file_name}")

    set(bpf_file_name ${file_name}.bpf.c)
    set(bpf_file_path ${CMAKE_CURRENT_SOURCE_DIR}/${bpf_file_name})
    set(bpf_obj_file_name ${file_name}.bpf.o)
    set(bpf_obj_file_path ${CMAKE_CURRENT_BINARY_DIR}/${bpf_obj_file_name})

    if (NOT EXISTS ${bpf_file_path})
        message(FATAL_ERROR "BPF file ${bpf_file_path} does not exist")
    endif()

    add_custom_command(
        OUTPUT ${bpf_obj_file_path}
        COMMAND ${clang_path} -g -O2 -target bpf -c ${bpf_file_path} -o ${bpf_obj_file_path}
        DEPENDS ${bpf_file_path}
        COMMENT "Building BPF object ${bpf_obj_file_path}"
    )

    add_custom_target(${file_name}_ELF ALL DEPENDS ${bpf_obj_file_path} SOURCES ${bpf_file_path})

    add_test(NAME ${file_name}_TEST_INTERPRET COMMAND "${CMAKE_BINARY_DIR}/bin/ubpf_test" "${bpf_obj_file_path}")
    set_tests_properties(${file_name}_TEST_INTERPRET PROPERTIES PASS_REGULAR_EXPRESSION "0x0")
    add_test(NAME ${file_name}_TEST_JIT COMMAND "${CMAKE_BINARY_DIR}/bin/ubpf_test" "${bpf_obj_file_path}")
    set_tests_properties(${file_name}_TEST_JIT PROPERTIES PASS_REGULAR_EXPRESSION "0x0")
endfunction()

if (CLANG_SUPPORTS_BPF)
    build_bpf(map)
endif()
