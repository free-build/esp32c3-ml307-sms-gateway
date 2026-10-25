idf_component_register(
    SRCS "upstream/src/pdulib.cpp" "pdu_c_adapter.cpp"
    INCLUDE_DIRS "upstream/src" "."
)

# PDUlib 是隔离的第三方 C++ 依赖；DESKTOP_PDU 避免引入 Arduino 专用头文件。
target_compile_definitions(${COMPONENT_LIB} PUBLIC DESKTOP_PDU)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-sign-compare -Wno-unused-variable)
