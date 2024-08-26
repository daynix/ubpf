add_executable("auto_test" test.cpp)

target_link_libraries("auto_test" PRIVATE "bpf" "ubpf")

target_include_directories("auto_test" PRIVATE "vm/inc/")