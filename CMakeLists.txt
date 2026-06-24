cmake_minimum_required(VERSION 3.20)

project(LunaAGPatch LANGUAGES CXX)

add_library(LunaAGPatch SHARED
    src/dllmain.cpp
)

target_compile_features(LunaAGPatch PRIVATE cxx_std_20)
target_compile_definitions(LunaAGPatch PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

if(MSVC)
    target_compile_options(LunaAGPatch PRIVATE /utf-8 /J /W4 /permissive-)
endif()

set_target_properties(LunaAGPatch PROPERTIES
    OUTPUT_NAME "LunaAG-Patch"
)
